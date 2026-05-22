use pyo3::prelude::*;
use pyo3::types::PyDict;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::QName;
use quick_xml::Reader;

#[derive(Default)]
struct RssItem {
    title: String,
    description: String,
    link: String,
    enclosure: String,
    size: i64,
    pubdate: String,
    nickname: String,
}

impl RssItem {
    fn has_output(&self) -> bool {
        !self.title.is_empty() && (!self.enclosure.is_empty() || !self.link.is_empty())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TextField {
    Title,
    Description,
    Link,
    Pubdate,
    Nickname,
}

/// 批量解析 RSS/Atom 条目，返回 Python 侧后续处理需要的核心字段。
#[pyfunction]
pub(crate) fn parse_rss_items_fast(
    py: Python<'_>,
    xml_text: &str,
    max_items: usize,
) -> PyResult<Option<Vec<PyObject>>> {
    let mut reader = Reader::from_str(xml_text);
    reader.config_mut().trim_text(true);

    let mut items = Vec::new();
    let mut current_item: Option<RssItem> = None;
    let mut current_field: Option<TextField> = None;
    let mut item_depth = 0usize;
    let mut parse_failed = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                let local = local_name(event.name());
                if current_item.is_none() && (local == "item" || local == "entry") {
                    current_item = Some(RssItem::default());
                    current_field = None;
                    item_depth = 1;
                    continue;
                }
                if let Some(item) = current_item.as_mut() {
                    item_depth += 1;
                    match local.as_str() {
                        "title" => current_field = Some(TextField::Title),
                        "description" | "summary" => current_field = Some(TextField::Description),
                        "pubDate" | "published" | "updated" => current_field = Some(TextField::Pubdate),
                        "creator" => current_field = Some(TextField::Nickname),
                        "link" => {
                            current_field = Some(TextField::Link);
                            if item.link.is_empty() {
                                if let Some(href) = attr_value(&event, QName(b"href")) {
                                    item.link = href;
                                }
                            }
                        }
                        "enclosure" => {
                            if let Some(url) = attr_value(&event, QName(b"url")) {
                                item.enclosure = url;
                            }
                            if let Some(length) = attr_value(&event, QName(b"length")) {
                                item.size = length.parse::<i64>().unwrap_or(0);
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::Empty(event)) => {
                if let Some(item) = current_item.as_mut() {
                    match local_name(event.name()).as_str() {
                        "link" => {
                            if item.link.is_empty() {
                                if let Some(href) = attr_value(&event, QName(b"href")) {
                                    item.link = href;
                                }
                            }
                        }
                        "enclosure" => {
                            if let Some(url) = attr_value(&event, QName(b"url")) {
                                item.enclosure = url;
                            }
                            if let Some(length) = attr_value(&event, QName(b"length")) {
                                item.size = length.parse::<i64>().unwrap_or(0);
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::Text(event)) => {
                if let (Some(item), Some(field)) = (current_item.as_mut(), current_field) {
                    if let Ok(value) = event.decode() {
                        append_field(item, field, value.as_ref());
                    }
                }
            }
            Ok(Event::CData(event)) => {
                if let (Some(item), Some(field)) = (current_item.as_mut(), current_field) {
                    if let Ok(value) = event.decode() {
                        append_field(item, field, value.as_ref());
                    }
                }
            }
            Ok(Event::End(event)) => {
                if current_item.is_some() {
                    let local = local_name(event.name());
                    if local == "item" || local == "entry" {
                        let mut item = current_item.take().unwrap_or_default();
                        if item.enclosure.is_empty() && !item.link.is_empty() {
                            item.enclosure = item.link.clone();
                        }
                        if item.has_output() {
                            items.push(item_to_py(py, &item)?.into_any().unbind());
                            if items.len() >= max_items {
                                break;
                            }
                        }
                        current_field = None;
                        item_depth = 0;
                    } else {
                        item_depth = item_depth.saturating_sub(1);
                        if item_depth <= 1 {
                            current_field = None;
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => {
                parse_failed = true;
                break;
            }
            _ => {}
        }
    }

    if parse_failed && items.is_empty() {
        Ok(None)
    } else {
        Ok(Some(items))
    }
}

/// 将内部 RSS 条目结构转换为 Python 字典。
fn item_to_py<'py>(py: Python<'py>, item: &RssItem) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("title", item.title.trim())?;
    dict.set_item("enclosure", item.enclosure.trim())?;
    dict.set_item("size", item.size)?;
    dict.set_item("description", item.description.trim())?;
    dict.set_item("link", item.link.trim())?;
    dict.set_item("pubdate_raw", item.pubdate.trim())?;
    if !item.nickname.trim().is_empty() {
        dict.set_item("nickname", item.nickname.trim())?;
    }
    Ok(dict)
}

/// 返回 XML 名称去掉命名空间前缀后的本地名称。
fn local_name(name: QName<'_>) -> String {
    let raw = name.as_ref();
    let local = raw.rsplit(|byte| *byte == b':').next().unwrap_or(raw);
    std::str::from_utf8(local).unwrap_or("").to_string()
}

/// 读取 XML 节点属性并完成实体反转义。
fn attr_value(event: &BytesStart<'_>, name: QName<'_>) -> Option<String> {
    event
        .try_get_attribute(name)
        .ok()
        .flatten()
        .and_then(|attr| attr.decode_and_unescape_value(event.decoder()).ok())
        .map(|value| value.into_owned())
}

/// 追加当前文本节点到对应 RSS 字段。
fn append_field(item: &mut RssItem, field: TextField, value: &str) {
    let target = match field {
        TextField::Title => &mut item.title,
        TextField::Description => &mut item.description,
        TextField::Link => &mut item.link,
        TextField::Pubdate => &mut item.pubdate,
        TextField::Nickname => &mut item.nickname,
    };
    target.push_str(value);
}
