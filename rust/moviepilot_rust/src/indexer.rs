use crate::utils::{get_optional_i64, get_optional_string, py_i64_to_usize};
use once_cell::sync::Lazy;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use regex::{Regex, RegexBuilder};
use scraper::{ElementRef, Html, Selector};
use url::form_urlencoded;
use url::Url;

const PATH_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

static IMDB_ID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^tt\d+$").unwrap());

static FILESIZE_UNIT_RE: Lazy<Regex> = Lazy::new(|| {
    RegexBuilder::new(r"[KMGTPI]*B?")
        .case_insensitive(true)
        .build()
        .unwrap()
});
static NUMERIC_FACTOR_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\d+\.?\d*)").unwrap());
static FIELD_EXPR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^fields(?:\.([A-Za-z0-9_]+)|\[\s*['"]([^'"]+)['"]\s*\])$"#).unwrap()
});
static JINJA_EXPR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\{\{-?\s*(.*?)\s*-?\}\}"#).unwrap());
static JINJA_TAG_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"\{%-?\s*(.*?)\s*-?%\}"#).unwrap());

enum RowParseResult {
    Unsupported,
    Empty,
    Item(PyObject),
}

/// 批量解析普通配置 indexer 页面，遇到不支持的选择器配置时返回 None 交给 Python 回退。
#[pyfunction]
#[pyo3(signature = (html_text, domain, list_config, fields, category=None, result_num=100))]
pub(crate) fn parse_indexer_torrents_fast(
    py: Python<'_>,
    html_text: &str,
    domain: &str,
    list_config: &Bound<'_, PyDict>,
    fields: &Bound<'_, PyDict>,
    category: Option<&Bound<'_, PyDict>>,
    result_num: usize,
) -> PyResult<Option<PyObject>> {
    let Some(list_selector_text) = get_optional_string(list_config, "selector")? else {
        return Ok(None);
    };
    if list_selector_text.is_empty() {
        return Ok(None);
    }
    let Ok(list_selector) = Selector::parse(&list_selector_text) else {
        return Ok(None);
    };
    let document = Html::parse_document(html_text);
    let result = PyList::empty(py);
    for row in document.select(&list_selector).take(result_num) {
        match parse_indexer_row(py, row, domain, fields, category)? {
            RowParseResult::Unsupported => return Ok(None),
            RowParseResult::Empty => {}
            RowParseResult::Item(item) => result.append(item)?,
        }
    }
    Ok(Some(result.into()))
}

/// 执行 indexer 文本过滤器，遇到 Python 专属过滤器时返回 None。
fn apply_text_filters(mut current: String, filters: &Bound<'_, PyAny>) -> PyResult<Option<String>> {
    let Ok(filter_list) = filters.downcast::<PyList>() else {
        return Ok(None);
    };
    for item in filter_list.iter() {
        let filter = item.downcast::<PyDict>()?;
        let method_name = get_optional_string(filter, "name")?;
        if current.is_empty() {
            break;
        }
        match method_name.as_deref() {
            Some("re_search") => {
                let Some(args) = filter.get_item("args")? else {
                    continue;
                };
                let Ok(args_list) = args.downcast::<PyList>() else {
                    continue;
                };
                if args_list.len() < 2 {
                    continue;
                }
                let pattern = args_list.get_item(0)?.extract::<String>()?;
                let group_index = py_i64_to_usize(&args_list.get_item(args_list.len() - 1)?)?;
                let regex =
                    Regex::new(&pattern).map_err(|err| PyValueError::new_err(err.to_string()))?;
                if let Some(captures) = regex.captures(&current) {
                    if let Some(value) = captures.get(group_index) {
                        current = value.as_str().to_string();
                    }
                }
            }
            Some("split") => {
                let Some(args) = filter.get_item("args")? else {
                    continue;
                };
                let Ok(args_list) = args.downcast::<PyList>() else {
                    continue;
                };
                if args_list.len() < 2 {
                    continue;
                }
                let delimiter = args_list.get_item(0)?.extract::<String>()?;
                let index = py_i64_to_usize(&args_list.get_item(args_list.len() - 1)?)?;
                if let Some(value) = current.split(&delimiter).nth(index) {
                    current = value.to_string();
                }
            }
            Some("replace") => {
                let Some(args) = filter.get_item("args")? else {
                    continue;
                };
                let Ok(args_list) = args.downcast::<PyList>() else {
                    continue;
                };
                if args_list.len() < 2 {
                    continue;
                }
                let from = args_list.get_item(0)?.extract::<String>()?;
                let to = args_list
                    .get_item(args_list.len() - 1)?
                    .extract::<String>()?;
                current = current.replace(&from, &to);
            }
            Some("strip") => {
                current = current.trim().to_string();
            }
            Some("appendleft") => {
                let Some(args) = filter.get_item("args")? else {
                    continue;
                };
                current = format!("{}{}", args.str()?.to_str()?, current);
            }
            Some("querystring") => {
                let Some(args) = filter.get_item("args")? else {
                    continue;
                };
                current = query_param_value(&current, args.str()?.to_str()?).unwrap_or_default();
            }
            Some("dateparse") => return Ok(None),
            _ => return Ok(None),
        }
    }
    Ok(Some(current.trim().to_string()))
}

/// 将文件大小文本转换为字节数，供 Rust HTML 解析内部共用。
fn parse_filesize_text(text: &str) -> i64 {
    let raw = text.trim().to_string();
    if raw.is_empty() {
        return 0;
    }
    if raw.chars().all(|ch| ch.is_ascii_digit()) {
        return raw.parse::<i64>().unwrap_or(0);
    }
    let normalized = raw.replace([',', ' '], "").to_uppercase();
    let size_text = FILESIZE_UNIT_RE.replace_all(&normalized, "").to_string();
    let Ok(mut size) = size_text.parse::<f64>() else {
        return 0;
    };
    if normalized.contains("PB") || normalized.contains("PIB") {
        size *= 1024_f64.powi(5);
    } else if normalized.contains("TB") || normalized.contains("TIB") {
        size *= 1024_f64.powi(4);
    } else if normalized.contains("GB") || normalized.contains("GIB") {
        size *= 1024_f64.powi(3);
    } else if normalized.contains("MB") || normalized.contains("MIB") {
        size *= 1024_f64.powi(2);
    } else if normalized.contains("KB") || normalized.contains("KIB") {
        size *= 1024_f64;
    }
    size.round() as i64
}

/// 根据普通 indexer 配置构造搜索或浏览 URL。
#[pyfunction]
pub(crate) fn build_indexer_search_url_fast(
    config: &Bound<'_, PyDict>,
) -> PyResult<Option<String>> {
    let Some(search_any) = config.get_item("search")? else {
        return Ok(None);
    };
    let search = search_any.downcast::<PyDict>()?;
    let domain = get_optional_string(config, "domain")?.unwrap_or_default();
    if domain.is_empty() {
        return Ok(None);
    }

    let keyword_any = config.get_item("keyword")?;
    let keyword_present = keyword_any.as_ref().is_some_and(|value| !value.is_none());
    let mut torrents_path = pick_torrents_path(search, config)?;
    let page = get_optional_i64(config, "page")?.unwrap_or(0);

    if keyword_present {
        let (mut search_word, search_mode) =
            build_search_word(config, keyword_any.as_ref().unwrap())?;
        let is_imdbid_search = IMDB_ID_RE.is_match(&search_word);
        search_word = format_search_word(search, &search_word)?;
        let params_any = search.get_item("params")?;
        let Some(params_obj) = params_any else {
            let encoded = utf8_percent_encode(&search_word, PATH_ENCODE_SET).to_string();
            return Ok(Some(format!(
                "{}{}",
                domain,
                torrents_path
                    .replace("{keyword}", &encoded)
                    .replace("{page}", &page.to_string())
            )));
        };
        let params_dict = params_obj.downcast::<PyDict>()?;
        if params_dict.is_empty() {
            let encoded = utf8_percent_encode(&search_word, PATH_ENCODE_SET).to_string();
            return Ok(Some(format!(
                "{}{}",
                domain,
                torrents_path
                    .replace("{keyword}", &encoded)
                    .replace("{page}", &page.to_string())
            )));
        }

        let mut query_params: Vec<(String, String)> = vec![
            ("search_mode".to_string(), search_mode.to_string()),
            ("search_area".to_string(), "0".to_string()),
            ("page".to_string(), page.to_string()),
            ("notnewword".to_string(), "1".to_string()),
        ];
        for (key, value) in params_dict.iter() {
            let key = key.extract::<String>()?;
            if key == "search_area" && !is_imdbid_search {
                continue;
            }
            let rendered = value.str()?.to_str()?.replace("{keyword}", &search_word);
            upsert_query_param(&mut query_params, key, rendered);
        }
        apply_category_params(config, &mut query_params)?;
        return Ok(Some(combine_url(&domain, &torrents_path, &query_params)?));
    }

    let browse_any = config.get_item("browse")?;
    if let Some(browse_obj) = browse_any {
        if !browse_obj.is_none() {
            let browse = browse_obj.downcast::<PyDict>()?;
            if let Some(path) = get_optional_string(browse, "path")? {
                torrents_path = path;
            }
            if let Some(start) = get_optional_i64(browse, "start")? {
                torrents_path = torrents_path.replace("{page}", &(start + page).to_string());
            }
        } else if page > 0 {
            torrents_path = format!("{torrents_path}?page={page}");
        }
    } else if page > 0 {
        torrents_path = format!("{torrents_path}?page={page}");
    }
    torrents_path = torrents_path
        .replace("{page}", &page.to_string())
        .replace("{keyword}", "");
    Ok(Some(format!("{domain}{torrents_path}")))
}

fn query_param_value(text: &str, key: &str) -> Option<String> {
    let query = if let Ok(url) = Url::parse(text) {
        url.query().unwrap_or("").to_string()
    } else {
        text.split_once('?')
            .map(|(_, query)| query.split('#').next().unwrap_or("").to_string())
            .unwrap_or_default()
    };
    form_urlencoded::parse(query.as_bytes())
        .find(|(param_key, _)| param_key == key)
        .map(|(_, value)| value.to_string())
}

/// 解析单行种子信息，覆盖普通配置站点的主字段抽取流程。
fn parse_indexer_row(
    py: Python<'_>,
    row: ElementRef<'_>,
    domain: &str,
    fields: &Bound<'_, PyDict>,
    category: Option<&Bound<'_, PyDict>>,
) -> PyResult<RowParseResult> {
    let output = PyDict::new(py);
    if !parse_title(py, row, fields, &output)? {
        return Ok(RowParseResult::Unsupported);
    }
    if !parse_description(py, row, fields, &output)? {
        return Ok(RowParseResult::Unsupported);
    }
    if !parse_link_field(
        py, row, fields, domain, "details", "page_url", true, &output,
    )? {
        return Ok(RowParseResult::Unsupported);
    }
    if !parse_link_field(
        py,
        row,
        fields,
        domain,
        "download",
        "enclosure",
        false,
        &output,
    )? {
        return Ok(RowParseResult::Unsupported);
    }
    if !parse_plain_field(py, row, fields, "imdbid", "imdbid", &output)? {
        return Ok(RowParseResult::Unsupported);
    }
    if !parse_size_field(py, row, fields, &output)? {
        return Ok(RowParseResult::Unsupported);
    }
    if !parse_int_field(py, row, fields, "leechers", "peers", &output)? {
        return Ok(RowParseResult::Unsupported);
    }
    if !parse_int_field(py, row, fields, "seeders", "seeders", &output)? {
        return Ok(RowParseResult::Unsupported);
    }
    if !parse_int_field(py, row, fields, "grabs", "grabs", &output)? {
        return Ok(RowParseResult::Unsupported);
    }
    if !parse_factor_field(py, row, fields, "downloadvolumefactor", &output)? {
        return Ok(RowParseResult::Unsupported);
    }
    if !parse_factor_field(py, row, fields, "uploadvolumefactor", &output)? {
        return Ok(RowParseResult::Unsupported);
    }
    if !parse_plain_field(py, row, fields, "date_added", "pubdate", &output)? {
        return Ok(RowParseResult::Unsupported);
    }
    if !parse_plain_field(py, row, fields, "date_elapsed", "date_elapsed", &output)? {
        return Ok(RowParseResult::Unsupported);
    }
    if !parse_plain_field(py, row, fields, "freedate", "freedate", &output)? {
        return Ok(RowParseResult::Unsupported);
    }
    if !parse_labels_field(py, row, fields, &output)? {
        return Ok(RowParseResult::Unsupported);
    }
    if !parse_hr_field(py, row, fields, &output)? {
        return Ok(RowParseResult::Unsupported);
    }
    if !parse_category_field(py, row, fields, category, &output)? {
        return Ok(RowParseResult::Unsupported);
    }
    if output.is_empty() {
        return Ok(RowParseResult::Empty);
    }
    Ok(RowParseResult::Item(output.into()))
}

/// 解析标题字段，支持直接 selector 和常见的 title_default/title_optional 模板。
fn parse_title(
    py: Python<'_>,
    row: ElementRef<'_>,
    fields: &Bound<'_, PyDict>,
    output: &Bound<'_, PyDict>,
) -> PyResult<bool> {
    let Some(selector) = get_field_dict(fields, "title")? else {
        return Ok(true);
    };
    let mut title = if selector.contains("selector")? {
        safe_query(row, &selector)?
    } else if let Some(template) = get_optional_string(&selector, "text")? {
        let Some(default_selector) = get_field_dict(fields, "title_default")? else {
            return Ok(false);
        };
        let title_default = safe_query(row, &default_selector)?.unwrap_or_default();
        let title_optional =
            if let Some(optional_selector) = get_field_dict(fields, "title_optional")? {
                safe_query(row, &optional_selector)?.unwrap_or_default()
            } else {
                String::new()
            };
        let Some(rendered) = render_known_template(
            &template,
            &[
                ("title_default", title_default.as_str()),
                ("title_optional", title_optional.as_str()),
            ],
        ) else {
            return Ok(false);
        };
        Some(rendered)
    } else {
        None
    };
    title = apply_selector_filters(py, title, &selector)?;
    if let Some(value) = title {
        output.set_item("title", value)?;
    }
    Ok(true)
}

/// 解析描述字段，支持直接 selector 和常见 description 模板。
fn parse_description(
    py: Python<'_>,
    row: ElementRef<'_>,
    fields: &Bound<'_, PyDict>,
    output: &Bound<'_, PyDict>,
) -> PyResult<bool> {
    let Some(selector) = get_field_dict(fields, "description")? else {
        return Ok(true);
    };
    let mut description = if selector.contains("selector")? || selector.contains("selectors")? {
        safe_query(row, &selector)?
    } else if let Some(template) = get_optional_string(&selector, "text")? {
        let mut values = Vec::new();
        for key in [
            "tags",
            "subject",
            "description_free_forever",
            "description_normal",
        ] {
            if let Some(field_selector) = get_field_dict(fields, key)? {
                let value = safe_query(row, &field_selector)?.unwrap_or_default();
                values.push((key.to_string(), value));
            }
        }
        let refs: Vec<(&str, &str)> = values
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        let Some(rendered) = render_known_template(&template, &refs) else {
            return Ok(false);
        };
        Some(rendered)
    } else {
        None
    };
    description = apply_selector_filters(py, description, &selector)?;
    if let Some(value) = description {
        output.set_item("description", value)?;
    }
    Ok(true)
}

/// 解析普通文本字段。
fn parse_plain_field(
    py: Python<'_>,
    row: ElementRef<'_>,
    fields: &Bound<'_, PyDict>,
    source_key: &str,
    target_key: &str,
    output: &Bound<'_, PyDict>,
) -> PyResult<bool> {
    let Some(selector) = get_field_dict(fields, source_key)? else {
        return Ok(true);
    };
    if selector.contains("text")? {
        return Ok(false);
    }
    let value = apply_selector_filters(py, safe_query(row, &selector)?, &selector)?;
    if let Some(value) = value {
        output.set_item(target_key, value.replace('\n', " ").trim().to_string())?;
    }
    Ok(true)
}

/// 解析详情和下载链接，并按 Python 逻辑拼接相对地址。
fn parse_link_field(
    py: Python<'_>,
    row: ElementRef<'_>,
    fields: &Bound<'_, PyDict>,
    domain: &str,
    source_key: &str,
    target_key: &str,
    protocol_relative: bool,
    output: &Bound<'_, PyDict>,
) -> PyResult<bool> {
    let Some(selector) = get_field_dict(fields, source_key)? else {
        return Ok(true);
    };
    let link = apply_selector_filters(py, safe_query(row, &selector)?, &selector)?;
    if let Some(link) = link {
        if link.is_empty() {
            return Ok(true);
        }
        output.set_item(
            target_key,
            normalize_site_link(domain, &link, protocol_relative),
        )?;
    }
    Ok(true)
}

/// 解析文件大小字段并转换为字节。
fn parse_size_field(
    py: Python<'_>,
    row: ElementRef<'_>,
    fields: &Bound<'_, PyDict>,
    output: &Bound<'_, PyDict>,
) -> PyResult<bool> {
    let Some(selector) = get_field_dict(fields, "size")? else {
        return Ok(true);
    };
    let value = apply_selector_filters(py, safe_query(row, &selector)?, &selector)?;
    let size = value
        .map(|item| parse_filesize_text(item.replace('\n', "").trim()))
        .unwrap_or(0);
    output.set_item("size", size)?;
    Ok(true)
}

/// 解析整数类字段，兼容 "12/34" 和千分位逗号。
fn parse_int_field(
    py: Python<'_>,
    row: ElementRef<'_>,
    fields: &Bound<'_, PyDict>,
    source_key: &str,
    target_key: &str,
    output: &Bound<'_, PyDict>,
) -> PyResult<bool> {
    let Some(selector) = get_field_dict(fields, source_key)? else {
        return Ok(true);
    };
    let value = apply_selector_filters(py, safe_query(row, &selector)?, &selector)?;
    let parsed = value
        .as_deref()
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("")
        .replace(',', "")
        .trim()
        .parse::<i64>()
        .unwrap_or(0);
    output.set_item(target_key, parsed)?;
    Ok(true)
}

/// 解析上传/下载优惠系数字段。
fn parse_factor_field(
    py: Python<'_>,
    row: ElementRef<'_>,
    fields: &Bound<'_, PyDict>,
    key: &str,
    output: &Bound<'_, PyDict>,
) -> PyResult<bool> {
    let Some(selector) = get_field_dict(fields, key)? else {
        return Ok(true);
    };
    output.set_item(key, 1)?;
    if let Some(case_obj) = selector.get_item("case")? {
        let case_dict = case_obj.downcast::<PyDict>()?;
        for (case_selector_obj, value) in case_dict.iter() {
            let case_selector = case_selector_obj.extract::<String>()?;
            if selector_exists(row, &case_selector)? {
                output.set_item(key, value)?;
                return Ok(true);
            }
        }
        return Ok(true);
    }
    let value = apply_selector_filters(py, safe_query(row, &selector)?, &selector)?;
    if let Some(value) = value {
        if let Some(caps) = NUMERIC_FACTOR_RE.captures(&value) {
            if let Some(number) = caps
                .get(1)
                .and_then(|item| item.as_str().parse::<i64>().ok())
            {
                output.set_item(key, number)?;
            }
        }
    }
    Ok(true)
}

/// 解析标签列表字段。
fn parse_labels_field(
    py: Python<'_>,
    row: ElementRef<'_>,
    fields: &Bound<'_, PyDict>,
    output: &Bound<'_, PyDict>,
) -> PyResult<bool> {
    let Some(selector) = get_field_dict(fields, "labels")? else {
        return Ok(true);
    };
    if !selector.contains("selector")? {
        output.set_item("labels", PyList::empty(py))?;
        return Ok(true);
    }
    let Some(values) = query_all_values(row, &selector)? else {
        output.set_item("labels", PyList::empty(py))?;
        return Ok(true);
    };
    let labels = PyList::empty(py);
    for value in values.into_iter().filter(|item| !item.is_empty()) {
        labels.append(value)?;
    }
    output.set_item("labels", labels)?;
    Ok(true)
}

/// 解析 HR 标记字段。
fn parse_hr_field(
    py: Python<'_>,
    row: ElementRef<'_>,
    fields: &Bound<'_, PyDict>,
    output: &Bound<'_, PyDict>,
) -> PyResult<bool> {
    let Some(selector) = get_field_dict(fields, "hr")? else {
        return Ok(true);
    };
    let Some(selector_text) = get_selector_text(&selector)? else {
        output.set_item("hit_and_run", false)?;
        return Ok(true);
    };
    output.set_item("hit_and_run", selector_exists(row, &selector_text)?)?;
    let _ = py;
    Ok(true)
}

/// 解析分类字段并映射为 MoviePilot 媒体类型中文值。
fn parse_category_field(
    py: Python<'_>,
    row: ElementRef<'_>,
    fields: &Bound<'_, PyDict>,
    category: Option<&Bound<'_, PyDict>>,
    output: &Bound<'_, PyDict>,
) -> PyResult<bool> {
    let Some(selector) = get_field_dict(fields, "category")? else {
        return Ok(true);
    };
    let value = apply_selector_filters(py, safe_query(row, &selector)?, &selector)?;
    let media_type = if let (Some(value), Some(category)) = (value.as_deref(), category) {
        let tv_cats = category_ids_for_field(category, "tv")?;
        let movie_cats = category_ids_for_field(category, "movie")?;
        if tv_cats.iter().any(|item| item == value) && !movie_cats.iter().any(|item| item == value)
        {
            "电视剧"
        } else if movie_cats.iter().any(|item| item == value) {
            "电影"
        } else {
            "未知"
        }
    } else {
        "未知"
    };
    output.set_item("category", media_type)?;
    Ok(true)
}

/// 获取字段配置字典。
fn get_field_dict<'py>(
    fields: &Bound<'py, PyDict>,
    key: &str,
) -> PyResult<Option<Bound<'py, PyDict>>> {
    let Some(value) = fields.get_item(key)? else {
        return Ok(None);
    };
    if value.is_none() {
        return Ok(None);
    }
    Ok(Some(value.downcast_into::<PyDict>()?))
}

/// 执行 selector 查询并返回第一个符合 index/contents 规则的文本。
fn safe_query(
    row: ElementRef<'_>,
    selector_config: &Bound<'_, PyDict>,
) -> PyResult<Option<String>> {
    let Some(values) = query_all_values(row, selector_config)? else {
        return Ok(None);
    };
    Ok(select_indexed_value(values, selector_config))
}

/// 查询 selector 的全部文本或属性值。
fn query_all_values(
    row: ElementRef<'_>,
    selector_config: &Bound<'_, PyDict>,
) -> PyResult<Option<Vec<String>>> {
    let Some(selector_text) = get_selector_text(selector_config)? else {
        return Ok(None);
    };
    let Ok(selector) = Selector::parse(&selector_text) else {
        return Ok(None);
    };
    let attribute = get_optional_string(selector_config, "attribute")?;
    let remove_selectors = parse_remove_selectors(selector_config)?;
    let mut values = Vec::new();
    for element in row.select(&selector) {
        if let Some(attribute) = attribute.as_deref() {
            values.push(element.value().attr(attribute).unwrap_or("").to_string());
        } else {
            values.push(normalize_element_text(element, &remove_selectors));
        }
    }
    Ok(Some(values))
}

/// 解析 remove 配置，支持逗号分隔的 CSS 选择器列表。
fn parse_remove_selectors(selector_config: &Bound<'_, PyDict>) -> PyResult<Vec<Selector>> {
    let Some(remove_text) = get_optional_string(selector_config, "remove")? else {
        return Ok(Vec::new());
    };
    let mut selectors = Vec::new();
    for item in remove_text.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let Ok(selector) = Selector::parse(item) else {
            return Ok(Vec::new());
        };
        selectors.push(selector);
    }
    Ok(selectors)
}

/// 读取 selector 或 selectors 配置。
fn get_selector_text(selector_config: &Bound<'_, PyDict>) -> PyResult<Option<String>> {
    if let Some(selector) = get_optional_string(selector_config, "selector")? {
        if !selector.is_empty() {
            return Ok(Some(selector));
        }
    }
    if let Some(selector) = get_optional_string(selector_config, "selectors")? {
        if !selector.is_empty() {
            return Ok(Some(selector));
        }
    }
    Ok(None)
}

/// 对查询结果应用 contents/index 规则。
fn select_indexed_value(
    values: Vec<String>,
    selector_config: &Bound<'_, PyDict>,
) -> Option<String> {
    if values.is_empty() {
        return None;
    }
    if let Ok(Some(contents)) = get_optional_i64(selector_config, "contents") {
        if let Some(first) = values.first() {
            let lines: Vec<&str> = first.split('\n').collect();
            return pick_indexed_item(&lines, contents).map(|item| item.to_string());
        }
    }
    if let Ok(Some(index)) = get_optional_i64(selector_config, "index") {
        return pick_indexed_item(&values, index).cloned();
    }
    values.first().cloned()
}

/// 按 Python 列表语义读取正负索引。
fn pick_indexed_item<T>(items: &[T], index: i64) -> Option<&T> {
    let len = items.len() as i64;
    let resolved = if index < 0 { len + index } else { index };
    if resolved < 0 {
        return None;
    }
    items.get(resolved as usize)
}

/// 应用字段配置中的 filters。
fn apply_selector_filters(
    py: Python<'_>,
    value: Option<String>,
    selector_config: &Bound<'_, PyDict>,
) -> PyResult<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some(filters) = selector_config.get_item("filters")? else {
        return Ok(Some(value));
    };
    if filters.is_none() {
        return Ok(Some(value));
    }
    let _ = py;
    apply_text_filters(value, &filters).map(|filtered| filtered.or_else(|| Some(String::new())))
}

/// 规范化元素文本，尽量接近 PyQuery.text() 输出。
fn normalize_element_text(element: ElementRef<'_>, remove_selectors: &[Selector]) -> String {
    let mut rendered = String::new();
    for node in element.descendants() {
        let Some(text_node) = node.value().as_text() else {
            continue;
        };
        if should_skip_text_node(
            node.parent().and_then(ElementRef::wrap),
            element,
            remove_selectors,
        ) {
            continue;
        }
        rendered.push_str(text_node);
    }
    normalize_whitespace(&rendered)
}

/// 折叠 PyQuery.text() 中的连续空白，保留元素相邻文本节点的直接拼接效果。
fn normalize_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<&str>>().join(" ")
}

/// 判断文本节点是否位于需要 remove 的元素子树中。
fn should_skip_text_node(
    mut parent: Option<ElementRef<'_>>,
    root: ElementRef<'_>,
    remove_selectors: &[Selector],
) -> bool {
    while let Some(element) = parent {
        if element == root {
            return false;
        }
        if remove_selectors
            .iter()
            .any(|selector| selector.matches(&element))
        {
            return true;
        }
        parent = element.parent().and_then(ElementRef::wrap);
    }
    false
}

/// 判断 row 内是否存在指定 selector。
fn selector_exists(row: ElementRef<'_>, selector_text: &str) -> PyResult<bool> {
    let Ok(selector) = Selector::parse(selector_text) else {
        return Ok(false);
    };
    Ok(row.select(&selector).next().is_some())
}

/// 拼接详情和下载链接。
fn normalize_site_link(domain: &str, link: &str, protocol_relative: bool) -> String {
    if link.starts_with("http") || link.starts_with("magnet") {
        return link.to_string();
    }
    if protocol_relative && link.starts_with("//") {
        let scheme = domain.split(':').next().unwrap_or("http");
        return format!("{scheme}:{link}");
    }
    if !protocol_relative {
        if let Ok(base) = Url::parse(&standardize_base_url(domain)) {
            if let Some(host) = base.host_str() {
                if link.contains(host) {
                    if link.starts_with('/') {
                        return format!("{}:{link}", base.scheme());
                    }
                    return format!("{}://{link}", base.scheme());
                }
            }
        }
    }
    if let Some(stripped) = link.strip_prefix('/') {
        format!("{domain}{stripped}")
    } else {
        format!("{domain}{link}")
    }
}

/// 渲染常见的 Jinja 字段模板，不支持复杂表达式时由调用方回退 Python。
fn render_known_template(template: &str, values: &[(&str, &str)]) -> Option<String> {
    if template.contains("{#") {
        return None;
    }
    let rendered = render_jinja_blocks(template, values)?;
    render_field_vars(&rendered, values)
}

/// 渲染站点解析配置里常见的 if/elif/else/endif 字段模板。
fn render_jinja_blocks(template: &str, values: &[(&str, &str)]) -> Option<String> {
    let mut result = String::new();
    let mut cursor = 0;
    while let Some(tag_match) = JINJA_TAG_RE.find_at(template, cursor) {
        result.push_str(&template[cursor..tag_match.start()]);
        let captures = JINJA_TAG_RE.captures(tag_match.as_str())?;
        let tag_content = captures.get(1)?.as_str().trim();
        let Some(condition) = tag_content.strip_prefix("if ") else {
            return None;
        };
        let block_end = find_matching_endif(template, tag_match.end())?;
        let body = &template[tag_match.end()..block_end.endif_start];
        let rendered_branch = render_if_body(body, condition, values)?;
        result.push_str(&rendered_branch);
        cursor = block_end.endif_end;
    }
    result.push_str(&template[cursor..]);
    Some(result)
}

/// 查找当前 if 块对应的 endif，允许内部再嵌套一层字段模板。
fn find_matching_endif(template: &str, from: usize) -> Option<JinjaBlockEnd> {
    let mut depth = 1;
    for tag_match in JINJA_TAG_RE.find_iter(&template[from..]) {
        let absolute_start = from + tag_match.start();
        let absolute_end = from + tag_match.end();
        let captures = JINJA_TAG_RE.captures(tag_match.as_str())?;
        let tag_content = captures.get(1)?.as_str().trim();
        if tag_content.starts_with("if ") {
            depth += 1;
        } else if tag_content == "endif" {
            depth -= 1;
            if depth == 0 {
                return Some(JinjaBlockEnd {
                    endif_start: absolute_start,
                    endif_end: absolute_end,
                });
            }
        }
    }
    None
}

/// 从 if 块中选出第一个满足条件的分支并继续渲染。
fn render_if_body(body: &str, first_condition: &str, values: &[(&str, &str)]) -> Option<String> {
    let branches = split_if_branches(body, first_condition)?;
    for branch in branches {
        let selected = match branch.condition {
            Some(condition) => eval_field_condition(&condition, values)?,
            None => true,
        };
        if selected {
            return render_known_template(&branch.content, values);
        }
    }
    Some(String::new())
}

/// 按同层级 elif/else 拆分 if 块，嵌套 if 内部的分支不会被误拆。
fn split_if_branches(body: &str, first_condition: &str) -> Option<Vec<JinjaBranch>> {
    let mut branches = Vec::new();
    let mut depth = 0;
    let mut current_condition = Some(first_condition.trim().to_string());
    let mut branch_start = 0;
    for tag_match in JINJA_TAG_RE.find_iter(body) {
        let captures = JINJA_TAG_RE.captures(tag_match.as_str())?;
        let tag_content = captures.get(1)?.as_str().trim();
        if tag_content.starts_with("if ") {
            depth += 1;
            continue;
        }
        if tag_content == "endif" {
            if depth == 0 {
                return None;
            }
            depth -= 1;
            continue;
        }
        if depth == 0 {
            if let Some(condition) = tag_content.strip_prefix("elif ") {
                branches.push(JinjaBranch {
                    condition: current_condition.take(),
                    content: body[branch_start..tag_match.start()].to_string(),
                });
                current_condition = Some(condition.trim().to_string());
                branch_start = tag_match.end();
            } else if tag_content == "else" {
                branches.push(JinjaBranch {
                    condition: current_condition.take(),
                    content: body[branch_start..tag_match.start()].to_string(),
                });
                current_condition = None;
                branch_start = tag_match.end();
            }
        }
    }
    branches.push(JinjaBranch {
        condition: current_condition,
        content: body[branch_start..].to_string(),
    });
    Some(branches)
}

/// 计算字段真值条件，覆盖站点模板里的 fields.xxx、not、and、or。
fn eval_field_condition(condition: &str, values: &[(&str, &str)]) -> Option<bool> {
    let trimmed = condition.trim();
    if trimmed.contains(" or ") {
        for part in trimmed.split(" or ") {
            if eval_field_condition(part, values)? {
                return Some(true);
            }
        }
        return Some(false);
    }
    if trimmed.contains(" and ") {
        for part in trimmed.split(" and ") {
            if !eval_field_condition(part, values)? {
                return Some(false);
            }
        }
        return Some(true);
    }
    eval_field_condition_atom(trimmed, values)
}

/// 计算单个字段条件，缺失字段按 Jinja Undefined 的假值处理。
fn eval_field_condition_atom(condition: &str, values: &[(&str, &str)]) -> Option<bool> {
    let (negated, expression) = if let Some(rest) = condition.trim().strip_prefix("not ") {
        (true, rest.trim())
    } else {
        (false, condition.trim())
    };
    let key = parse_field_key(expression)?;
    let value = get_template_value(values, &key).unwrap_or_default();
    let truthy = !value.is_empty();
    Some(if negated { !truthy } else { truthy })
}

/// 替换模板中的 fields 变量，存在未知变量语法时回退 Python。
fn render_field_vars(template: &str, values: &[(&str, &str)]) -> Option<String> {
    let mut rendered = String::new();
    let mut cursor = 0;
    for captures in JINJA_EXPR_RE.captures_iter(template) {
        let whole = captures.get(0)?;
        rendered.push_str(&template[cursor..whole.start()]);
        let expression = captures.get(1)?.as_str();
        rendered.push_str(&eval_field_output(expression, values)?);
        cursor = whole.end();
    }
    rendered.push_str(&template[cursor..]);
    if rendered.contains("{{") || rendered.contains("{%") {
        return None;
    }
    Some(rendered)
}

/// 渲染输出表达式，覆盖字段变量、字段三元表达式和字符串拼接。
fn eval_field_output(expression: &str, values: &[(&str, &str)]) -> Option<String> {
    let expression = expression.trim();
    if let Some((true_expr, condition, false_expr)) = split_inline_if(expression) {
        if eval_field_condition(condition, values)? {
            return eval_field_output(true_expr, values);
        }
        return eval_field_output(false_expr, values);
    }
    let terms = split_concat_terms(expression)?;
    if terms.len() > 1 {
        let mut rendered = String::new();
        for term in terms {
            rendered.push_str(&eval_field_atom(term, values)?);
        }
        return Some(rendered);
    }
    eval_field_atom(expression, values)
}

/// 拆分 Jinja 的简单三元表达式：a if cond else b。
fn split_inline_if(expression: &str) -> Option<(&str, &str, &str)> {
    let (true_expr, right) = expression.split_once(" if ")?;
    let (condition, false_expr) = right.split_once(" else ")?;
    Some((true_expr.trim(), condition.trim(), false_expr.trim()))
}

/// 按字符串字面量边界拆分加号拼接表达式。
fn split_concat_terms(expression: &str) -> Option<Vec<&str>> {
    let mut terms = Vec::new();
    let mut start = 0;
    let mut quote: Option<char> = None;
    for (index, ch) in expression.char_indices() {
        if let Some(current_quote) = quote {
            if ch == current_quote {
                quote = None;
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            continue;
        }
        if ch == '+' {
            let term = expression[start..index].trim();
            if term.is_empty() {
                return None;
            }
            terms.push(term);
            start = index + ch.len_utf8();
        }
    }
    if quote.is_some() {
        return None;
    }
    let term = expression[start..].trim();
    if term.is_empty() {
        return None;
    }
    terms.push(term);
    Some(terms)
}

/// 渲染字段或字符串字面量，其他表达式交给 Python 回退。
fn eval_field_atom(expression: &str, values: &[(&str, &str)]) -> Option<String> {
    let expression = expression.trim();
    if let Some(value) = parse_string_literal(expression) {
        return Some(value);
    }
    let key = parse_field_key(expression)?;
    Some(get_template_value(values, &key).unwrap_or_default().to_string())
}

/// 解析单引号或双引号字符串字面量。
fn parse_string_literal(expression: &str) -> Option<String> {
    let mut chars = expression.chars();
    let quote = chars.next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    if !expression.ends_with(quote) || expression.len() < 2 {
        return None;
    }
    let inner = &expression[quote.len_utf8()..expression.len() - quote.len_utf8()];
    Some(inner.to_string())
}

/// 解析 fields 变量名，拒绝函数调用和比较表达式等完整 Jinja 能力。
fn parse_field_key(expression: &str) -> Option<String> {
    let captures = FIELD_EXPR_RE.captures(expression.trim())?;
    captures
        .get(1)
        .or_else(|| captures.get(2))
        .map(|item| item.as_str().to_string())
}

/// 从模板上下文中获取字段值，缺失字段按 Jinja 的空值处理。
fn get_template_value<'a>(values: &'a [(&str, &str)], template_key: &str) -> Option<&'a str> {
    for (field_key, value) in values {
        if *field_key == template_key {
            return Some(*value);
        }
    }
    None
}

struct JinjaBlockEnd {
    endif_start: usize,
    endif_end: usize,
}

struct JinjaBranch {
    condition: Option<String>,
    content: String,
}

/// 读取分类配置中的 ID 列表。
fn category_ids_for_field(category: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<String>> {
    let Some(list_obj) = category.get_item(key)? else {
        return Ok(Vec::new());
    };
    let Ok(list) = list_obj.downcast::<PyList>() else {
        return Ok(Vec::new());
    };
    let mut values = Vec::new();
    for item in list.iter() {
        let dict = item.downcast::<PyDict>()?;
        if let Some(id) = get_optional_string(dict, "id")? {
            values.push(id);
        }
    }
    Ok(values)
}

/// 从 indexer paths 配置中选择搜索路径。
fn pick_torrents_path(search: &Bound<'_, PyDict>, config: &Bound<'_, PyDict>) -> PyResult<String> {
    let Some(paths_obj) = search.get_item("paths")? else {
        return Ok(String::new());
    };
    let paths = paths_obj.downcast::<PyList>()?;
    if paths.len() == 1 {
        let path_item = paths.get_item(0)?;
        let path_dict = path_item.downcast::<PyDict>()?;
        return Ok(get_optional_string(path_dict, "path")?.unwrap_or_default());
    }
    let mtype = get_optional_string(config, "mtype")?;
    for item in paths.iter() {
        let path = item.downcast::<PyDict>()?;
        let path_type = get_optional_string(path, "type")?;
        if path_type.as_deref() == Some("all") && mtype.is_none() {
            return Ok(get_optional_string(path, "path")?.unwrap_or_default());
        }
        if path_type.as_deref() == Some("movie") && mtype.as_deref() == Some("电影") {
            return Ok(get_optional_string(path, "path")?.unwrap_or_default());
        }
        if path_type.as_deref() == Some("tv") && mtype.as_deref() == Some("电视剧") {
            return Ok(get_optional_string(path, "path")?.unwrap_or_default());
        }
    }
    Ok(String::new())
}

/// 根据关键字、批量配置构造搜索词和搜索模式。
fn build_search_word(
    config: &Bound<'_, PyDict>,
    keyword: &Bound<'_, PyAny>,
) -> PyResult<(String, i64)> {
    if let Ok(values) = keyword.extract::<Vec<String>>() {
        let batch = config.get_item("batch")?;
        let (delimiter, space_replace) = if let Some(batch_obj) = batch {
            if batch_obj.is_none() {
                (" ".to_string(), " ".to_string())
            } else {
                let batch_dict = batch_obj.downcast::<PyDict>()?;
                (
                    get_optional_string(batch_dict, "delimiter")?
                        .unwrap_or_else(|| " ".to_string()),
                    get_optional_string(batch_dict, "space_replace")?
                        .unwrap_or_else(|| " ".to_string()),
                )
            }
        } else {
            (" ".to_string(), " ".to_string())
        };
        let words: Vec<String> = values
            .into_iter()
            .map(|value| value.replace(' ', &space_replace))
            .collect();
        return Ok((words.join(&delimiter), 1));
    }
    Ok((keyword.str()?.to_str()?.to_string(), 0))
}

/// 按 imdbid_format 转换 IMDb ID 搜索词。
fn format_search_word(search: &Bound<'_, PyDict>, search_word: &str) -> PyResult<String> {
    if !IMDB_ID_RE.is_match(search_word) {
        return Ok(search_word.to_string());
    }
    let Some(format) = get_optional_string(search, "imdbid_format")? else {
        return Ok(search_word.to_string());
    };
    Ok(format
        .replace("{keyword}", search_word)
        .replace("{imdbid}", search_word)
        .replace("{imdbid_num}", search_word.trim_start_matches("tt")))
}

/// 更新查询参数，保留 Python dict update 的覆盖语义。
fn upsert_query_param(params: &mut Vec<(String, String)>, key: String, value: String) {
    if let Some((_, existing_value)) = params
        .iter_mut()
        .find(|(existing_key, _)| existing_key == &key)
    {
        *existing_value = value;
        return;
    }
    params.push((key, value));
}

/// 应用电影/电视剧分类查询参数。
fn apply_category_params(
    config: &Bound<'_, PyDict>,
    params: &mut Vec<(String, String)>,
) -> PyResult<()> {
    let Some(category_obj) = config.get_item("category")? else {
        return Ok(());
    };
    if category_obj.is_none() {
        return Ok(());
    }
    let category = category_obj.downcast::<PyDict>()?;
    let mtype = get_optional_string(config, "mtype")?;
    let cat_ids = collect_category_ids(category, mtype.as_deref())?;
    let allowed = get_optional_string(config, "cat")?.map(|value| {
        value
            .split(',')
            .map(|item| item.to_string())
            .collect::<Vec<String>>()
    });
    for cat_id in cat_ids {
        if cat_id.is_empty() {
            continue;
        }
        if let Some(allowed_cats) = &allowed {
            if !allowed_cats.iter().any(|item| item == &cat_id) {
                continue;
            }
        }
        if let Some(field) = get_optional_string(category, "field")? {
            let delimiter =
                get_optional_string(category, "delimiter")?.unwrap_or_else(|| " ".to_string());
            let current = params
                .iter()
                .find(|(key, _)| key == &field)
                .map(|(_, value)| value.clone())
                .unwrap_or_default();
            upsert_query_param(params, field, format!("{current}{delimiter}{cat_id}"));
        } else {
            upsert_query_param(params, format!("cat{cat_id}"), "1".to_string());
        }
    }
    Ok(())
}

/// 收集当前媒体类型可用的分类 ID。
fn collect_category_ids(
    category: &Bound<'_, PyDict>,
    mtype: Option<&str>,
) -> PyResult<Vec<String>> {
    let mut items = Vec::new();
    let keys = match mtype {
        Some("电视剧") => vec!["tv"],
        Some("电影") => vec!["movie"],
        _ => vec!["movie", "tv"],
    };
    for key in keys {
        if let Some(list_obj) = category.get_item(key)? {
            if let Ok(list) = list_obj.downcast::<PyList>() {
                for item in list.iter() {
                    let cat = item.downcast::<PyDict>()?;
                    if let Some(cat_id) = get_optional_string(cat, "id")? {
                        items.push(cat_id);
                    }
                }
            }
        }
    }
    Ok(items)
}

/// 合并 host、path 和查询参数。
fn combine_url(host: &str, path: &str, query: &[(String, String)]) -> PyResult<String> {
    let base = standardize_base_url(host);
    let mut url = Url::parse(&base)
        .and_then(|base_url| base_url.join(path))
        .map_err(|err| PyValueError::new_err(err.to_string()))?;
    let mut query_params: Vec<(String, String)> = url
        .query_pairs()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
    for (key, value) in query {
        upsert_query_param(&mut query_params, key.clone(), value.clone());
    }
    {
        let mut pairs = url.query_pairs_mut();
        pairs.clear();
        for (key, value) in query_params {
            pairs.append_pair(&key, &value);
        }
    }
    Ok(url.to_string())
}

/// 标准化基础 URL，与 Python UrlUtils.standardize_base_url 保持一致。
fn standardize_base_url(host: &str) -> String {
    let mut value = host.to_string();
    if !value.ends_with('/') {
        value.push('/');
    }
    if !value.starts_with("http://") && !value.starts_with("https://") {
        value = format!("http://{value}");
    }
    value
}
