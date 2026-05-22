use crate::utils::{get_optional_f64, get_optional_i64, get_optional_string};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};
use regex::{Regex, RegexBuilder};
use std::collections::HashMap;

#[derive(Clone, Debug)]
enum RuleExpr {
    Name(String),
    Not(Box<RuleExpr>),
    And(Box<RuleExpr>, Box<RuleExpr>),
    Or(Box<RuleExpr>, Box<RuleExpr>),
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Name(String),
    Not,
    And,
    Or,
    LParen,
    RParen,
}

#[derive(Clone, Debug)]
struct TorrentPayload {
    index: usize,
    title: String,
    description: String,
    labels: Vec<String>,
    size: f64,
    seeders: i64,
    downloadvolumefactor: Option<f64>,
    pub_minutes: f64,
    episode_count: f64,
    fields: HashMap<String, FieldValue>,
}

#[derive(Clone, Debug)]
enum FieldValue {
    Scalar(String),
    List(Vec<String>),
}

#[pyfunction]
pub(crate) fn parse_filter_rule_fast(py: Python<'_>, expression: &str) -> PyResult<PyObject> {
    let tokens = tokenize_rule(expression)?;
    let mut parser = RuleParserState::new(tokens);
    let expr = parser.parse_expression()?;
    if parser.has_remaining() {
        return Err(PyValueError::new_err("规则表达式包含无法解析的剩余内容"));
    }
    let outer = PyList::empty(py);
    outer.append(expr_to_py(py, &expr)?)?;
    Ok(outer.into())
}

/// 批量执行种子过滤规则，返回保留项的原始下标和优先级。
#[pyfunction]
#[pyo3(signature = (rule_set, rule_strings, torrents, media_info=None))]
pub(crate) fn filter_torrents_fast(
    py: Python<'_>,
    rule_set: &Bound<'_, PyDict>,
    rule_strings: Vec<String>,
    torrents: &Bound<'_, PyList>,
    media_info: Option<&Bound<'_, PyDict>>,
) -> PyResult<PyObject> {
    py.allow_threads(|| {});
    let mut payloads = Vec::with_capacity(torrents.len());
    for index in 0..torrents.len() {
        let item = torrents.get_item(index)?;
        let dict = item.downcast::<PyDict>()?;
        payloads.push(TorrentPayload::from_py_dict(index, dict)?);
    }

    let mut expr_cache: HashMap<String, RuleExpr> = HashMap::new();
    let mut regex_cache: HashMap<String, Regex> = HashMap::new();
    let mut current_indices: Vec<usize> = (0..payloads.len()).collect();
    let mut priorities: HashMap<usize, i64> = HashMap::new();

    for rule_string in rule_strings {
        if current_indices.is_empty() {
            break;
        }
        let levels: Vec<String> = rule_string
            .split('>')
            .map(|level| level.trim().to_string())
            .collect();
        let mut retained = Vec::new();
        for payload_index in &current_indices {
            let payload = &payloads[*payload_index];
            let mut res_order = 100_i64;
            let mut matched = false;
            for level in &levels {
                let expr = if let Some(cached) = expr_cache.get(level) {
                    cached.clone()
                } else {
                    let parsed = parse_rule_expression(level)?;
                    expr_cache.insert(level.clone(), parsed.clone());
                    parsed
                };
                if match_expr(&expr, payload, rule_set, media_info, &mut regex_cache)? {
                    matched = true;
                    priorities.insert(payload.index, res_order);
                    break;
                }
                res_order -= 1;
            }
            if matched {
                retained.push(*payload_index);
            }
        }
        current_indices = retained;
    }

    let result = PyList::empty(py);
    for payload_index in current_indices {
        let payload = &payloads[payload_index];
        result.append((
            payload.index,
            priorities.get(&payload.index).copied().unwrap_or(0),
        ))?;
    }
    Ok(result.into())
}

fn parse_rule_expression(expression: &str) -> PyResult<RuleExpr> {
    let tokens = tokenize_rule(expression)?;
    let mut parser = RuleParserState::new(tokens);
    let expr = parser.parse_expression()?;
    if parser.has_remaining() {
        return Err(PyValueError::new_err("规则表达式包含无法解析的剩余内容"));
    }
    Ok(expr)
}

/// 将规则字符串切分为名称、逻辑符和括号。
fn tokenize_rule(expression: &str) -> PyResult<Vec<Token>> {
    let chars: Vec<char> = expression.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        if ch.is_whitespace() {
            index += 1;
            continue;
        }
        match ch {
            '!' => {
                tokens.push(Token::Not);
                index += 1;
            }
            '&' => {
                tokens.push(Token::And);
                index += 1;
            }
            '|' => {
                tokens.push(Token::Or);
                index += 1;
            }
            '(' => {
                tokens.push(Token::LParen);
                index += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                index += 1;
            }
            _ => {
                let start = index;
                while index < chars.len() && chars[index].is_ascii_alphanumeric() {
                    index += 1;
                }
                if start == index {
                    return Err(PyValueError::new_err(format!("非法规则字符: {ch}")));
                }
                let name: String = chars[start..index].iter().collect();
                if !is_valid_rule_name(&name) {
                    return Err(PyValueError::new_err(format!("非法规则名称: {name}")));
                }
                tokens.push(Token::Name(name));
            }
        }
    }
    if tokens.is_empty() {
        return Err(PyValueError::new_err("规则表达式不能为空"));
    }
    Ok(tokens)
}

/// 判断规则名称是否符合原 pyparsing 语法。
fn is_valid_rule_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if first.is_ascii_alphabetic() {
        return chars.all(|ch| ch.is_ascii_alphanumeric());
    }
    if first.is_ascii_digit() {
        let mut seen_alpha = false;
        for ch in name.chars().skip_while(|ch| ch.is_ascii_digit()) {
            if !ch.is_ascii_alphanumeric() {
                return false;
            }
            if ch.is_ascii_alphabetic() {
                seen_alpha = true;
            }
        }
        return seen_alpha;
    }
    false
}

struct RuleParserState {
    tokens: Vec<Token>,
    index: usize,
}

impl RuleParserState {
    /// 创建规则解析器状态。
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, index: 0 }
    }

    /// 解析完整表达式。
    fn parse_expression(&mut self) -> PyResult<RuleExpr> {
        self.parse_or()
    }

    /// 返回是否还有未消费 token。
    fn has_remaining(&self) -> bool {
        self.index < self.tokens.len()
    }

    /// 解析 or 表达式。
    fn parse_or(&mut self) -> PyResult<RuleExpr> {
        let mut expr = self.parse_and()?;
        while self.consume(&Token::Or) {
            let right = self.parse_and()?;
            expr = RuleExpr::Or(Box::new(expr), Box::new(right));
        }
        Ok(expr)
    }

    /// 解析 and 表达式。
    fn parse_and(&mut self) -> PyResult<RuleExpr> {
        let mut expr = self.parse_not()?;
        while self.consume(&Token::And) {
            let right = self.parse_not()?;
            expr = RuleExpr::And(Box::new(expr), Box::new(right));
        }
        Ok(expr)
    }

    /// 解析 not 表达式。
    fn parse_not(&mut self) -> PyResult<RuleExpr> {
        if self.consume(&Token::Not) {
            return Ok(RuleExpr::Not(Box::new(self.parse_not()?)));
        }
        self.parse_primary()
    }

    /// 解析原子或括号表达式。
    fn parse_primary(&mut self) -> PyResult<RuleExpr> {
        let Some(token) = self.tokens.get(self.index).cloned() else {
            return Err(PyValueError::new_err("规则表达式意外结束"));
        };
        match token {
            Token::Name(name) => {
                self.index += 1;
                Ok(RuleExpr::Name(name))
            }
            Token::LParen => {
                self.index += 1;
                let expr = self.parse_expression()?;
                if !self.consume(&Token::RParen) {
                    return Err(PyValueError::new_err("规则表达式缺少右括号"));
                }
                Ok(expr)
            }
            _ => Err(PyValueError::new_err("规则表达式缺少规则名称")),
        }
    }

    /// 如果下一个 token 匹配则消费它。
    fn consume(&mut self, token: &Token) -> bool {
        if self.tokens.get(self.index) == Some(token) {
            self.index += 1;
            return true;
        }
        false
    }
}

/// 将规则 AST 转换为 Python 兼容嵌套列表。
fn expr_to_py(py: Python<'_>, expr: &RuleExpr) -> PyResult<PyObject> {
    match expr {
        RuleExpr::Name(name) => Ok(PyString::new(py, name).into_any().unbind()),
        RuleExpr::Not(inner) => {
            let list = PyList::empty(py);
            list.append("not")?;
            list.append(expr_to_py(py, inner)?)?;
            Ok(list.into())
        }
        RuleExpr::And(left, right) => expr_binary_to_py(py, "and", left, right),
        RuleExpr::Or(left, right) => expr_binary_to_py(py, "or", left, right),
    }
}

/// 将二元规则 AST 转换为 Python 兼容嵌套列表。
fn expr_binary_to_py(
    py: Python<'_>,
    operator: &str,
    left: &RuleExpr,
    right: &RuleExpr,
) -> PyResult<PyObject> {
    let list = PyList::empty(py);
    list.append(expr_to_py(py, left)?)?;
    list.append(operator)?;
    list.append(expr_to_py(py, right)?)?;
    Ok(list.into())
}

impl TorrentPayload {
    /// 从 Python 字典构造 Rust 过滤载荷。
    fn from_py_dict(index: usize, dict: &Bound<'_, PyDict>) -> PyResult<Self> {
        let title = get_optional_string(dict, "title")?.unwrap_or_default();
        let description = get_optional_string(dict, "description")?.unwrap_or_default();
        let labels = get_string_list(dict, "labels")?;
        let size = get_optional_f64(dict, "size")?.unwrap_or(0.0);
        let seeders = get_optional_i64(dict, "seeders")?.unwrap_or(0);
        let downloadvolumefactor = get_optional_f64(dict, "downloadvolumefactor")?;
        let pub_minutes = get_optional_f64(dict, "pub_minutes")?.unwrap_or(0.0);
        let episode_count = get_optional_f64(dict, "episode_count")?
            .unwrap_or(1.0)
            .max(1.0);
        let mut fields = HashMap::new();
        for (key, value) in dict.iter() {
            let key = key.extract::<String>()?;
            if value.is_none() {
                continue;
            }
            if let Ok(values) = value.extract::<Vec<String>>() {
                fields.insert(key, FieldValue::List(values));
            } else {
                fields.insert(key, FieldValue::Scalar(value.str()?.to_str()?.to_string()));
            }
        }
        Ok(Self {
            index,
            title,
            description,
            labels,
            size,
            seeders,
            downloadvolumefactor,
            pub_minutes,
            episode_count,
            fields,
        })
    }

    /// 返回指定字段的匹配文本。
    fn content_for_matches(&self, match_fields: &[String]) -> String {
        if match_fields.is_empty() {
            return format!(
                "{} {} {}",
                self.title,
                self.description,
                self.labels.join(" ")
            );
        }
        let mut parts = Vec::new();
        for field in match_fields {
            if let Some(value) = self.fields.get(field) {
                match value {
                    FieldValue::Scalar(text) => {
                        if !text.is_empty() {
                            parts.push(text.clone());
                        }
                    }
                    FieldValue::List(values) => {
                        parts.extend(values.iter().filter(|v| !v.is_empty()).cloned())
                    }
                }
            }
        }
        parts.join(" ")
    }
}

/// 从 Python 字典读取字符串列表。
fn get_string_list(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<String>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(Vec::new());
    };
    if value.is_none() {
        return Ok(Vec::new());
    }
    if let Ok(values) = value.extract::<Vec<String>>() {
        return Ok(values);
    }
    Ok(vec![value.str()?.to_str()?.to_string()])
}

/// 执行规则 AST 匹配。
fn match_expr(
    expr: &RuleExpr,
    torrent: &TorrentPayload,
    rule_set: &Bound<'_, PyDict>,
    media_info: Option<&Bound<'_, PyDict>>,
    regex_cache: &mut HashMap<String, Regex>,
) -> PyResult<bool> {
    match expr {
        RuleExpr::Name(name) => match_rule(name, torrent, rule_set, media_info, regex_cache),
        RuleExpr::Not(inner) => Ok(!match_expr(
            inner,
            torrent,
            rule_set,
            media_info,
            regex_cache,
        )?),
        RuleExpr::And(left, right) => {
            Ok(
                match_expr(left, torrent, rule_set, media_info, regex_cache)?
                    && match_expr(right, torrent, rule_set, media_info, regex_cache)?,
            )
        }
        RuleExpr::Or(left, right) => {
            Ok(
                match_expr(left, torrent, rule_set, media_info, regex_cache)?
                    || match_expr(right, torrent, rule_set, media_info, regex_cache)?,
            )
        }
    }
}

/// 执行单条规则匹配。
fn match_rule(
    rule_name: &str,
    torrent: &TorrentPayload,
    rule_set: &Bound<'_, PyDict>,
    media_info: Option<&Bound<'_, PyDict>>,
    regex_cache: &mut HashMap<String, Regex>,
) -> PyResult<bool> {
    let Some(rule_obj) = rule_set.get_item(rule_name)? else {
        return Ok(false);
    };
    let rule = rule_obj.downcast::<PyDict>()?;
    if let Some(tmdb_obj) = rule.get_item("tmdb")? {
        if !tmdb_obj.is_none() {
            if let Ok(tmdb) = tmdb_obj.downcast::<PyDict>() {
                if match_tmdb(tmdb, media_info)? {
                    return Ok(true);
                }
            }
        }
    }

    let match_fields = get_string_list(rule, "match")?;
    let content = torrent.content_for_matches(&match_fields);
    let includes = get_string_list(rule, "include")?;
    let excludes = get_string_list(rule, "exclude")?;

    if !includes.is_empty() {
        let mut included = false;
        for pattern in &includes {
            if regex_search(pattern, &content, regex_cache)? {
                included = true;
                break;
            }
        }
        if !included {
            return Ok(false);
        }
    }
    for exclude in excludes {
        if regex_search(&exclude, &content, regex_cache)? {
            return Ok(false);
        }
    }
    if let Some(size_range) = get_optional_string(rule, "size_range")? {
        if !match_size(torrent, &size_range)? {
            return Ok(false);
        }
    }
    if let Some(seeders) = get_optional_i64(rule, "seeders")? {
        if torrent.seeders < seeders {
            return Ok(false);
        }
    }
    if let Some(downloadvolumefactor) = get_optional_f64(rule, "downloadvolumefactor")? {
        if torrent.downloadvolumefactor != Some(downloadvolumefactor) {
            return Ok(false);
        }
    }
    if let Some(pubdate) = get_optional_string(rule, "publish_time")? {
        if !match_publish_time(torrent.pub_minutes, &pubdate) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// 使用带缓存的忽略大小写正则搜索。
fn regex_search(
    pattern: &str,
    content: &str,
    cache: &mut HashMap<String, Regex>,
) -> PyResult<bool> {
    if !cache.contains_key(pattern) {
        let regex = RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
        cache.insert(pattern.to_string(), regex);
    }
    Ok(cache
        .get(pattern)
        .is_some_and(|regex| regex.is_match(content)))
}

/// 匹配 TMDB 媒体属性规则。
fn match_tmdb(tmdb: &Bound<'_, PyDict>, media_info: Option<&Bound<'_, PyDict>>) -> PyResult<bool> {
    let Some(media) = media_info else {
        return Ok(false);
    };
    for (attr, value) in tmdb.iter() {
        if value.is_none() {
            continue;
        }
        let attr_name = attr.extract::<String>()?;
        let expected = value.str()?.to_str()?.to_string();
        if expected.is_empty() {
            continue;
        }
        let info_values = media_values(media, &attr_name)?;
        if info_values.is_empty() {
            return Ok(false);
        }
        let expected_values: Vec<String> = expected
            .split(',')
            .filter(|item| !item.is_empty())
            .map(|item| item.to_uppercase())
            .collect();
        if !expected_values.iter().any(|expected_item| {
            info_values
                .iter()
                .any(|info_item| info_item == expected_item)
        }) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// 获取媒体属性的可比较字符串集合。
fn media_values(media: &Bound<'_, PyDict>, attr_name: &str) -> PyResult<Vec<String>> {
    let Some(value) = media.get_item(attr_name)? else {
        return Ok(Vec::new());
    };
    if value.is_none() {
        return Ok(Vec::new());
    }
    if attr_name == "production_countries" {
        let Ok(items) = value.downcast::<PyList>() else {
            return Ok(Vec::new());
        };
        let mut values = Vec::new();
        for item in items.iter() {
            if let Ok(dict) = item.downcast::<PyDict>() {
                if let Some(country) = dict.get_item("iso_3166_1")? {
                    values.push(country.str()?.to_str()?.to_uppercase());
                }
            }
        }
        return Ok(values);
    }
    if let Ok(items) = value.extract::<Vec<String>>() {
        return Ok(items.into_iter().map(|item| item.to_uppercase()).collect());
    }
    Ok(vec![value.str()?.to_str()?.to_uppercase()])
}

/// 按每集大小匹配大小范围规则。
fn match_size(torrent: &TorrentPayload, size_range: &str) -> PyResult<bool> {
    let torrent_size = torrent.size / torrent.episode_count;
    let size_range = size_range.trim();
    let unit = 1024.0 * 1024.0;
    if let Some((min, max)) = size_range.split_once('-') {
        let min = min
            .trim()
            .parse::<f64>()
            .map_err(|err| PyValueError::new_err(err.to_string()))?
            * unit;
        let max = max
            .trim()
            .parse::<f64>()
            .map_err(|err| PyValueError::new_err(err.to_string()))?
            * unit;
        return Ok(min <= torrent_size && torrent_size <= max);
    }
    if let Some(min) = size_range.strip_prefix('>') {
        let min = min
            .trim()
            .parse::<f64>()
            .map_err(|err| PyValueError::new_err(err.to_string()))?
            * unit;
        return Ok(torrent_size >= min);
    }
    if let Some(max) = size_range.strip_prefix('<') {
        let max = max
            .trim()
            .parse::<f64>()
            .map_err(|err| PyValueError::new_err(err.to_string()))?
            * unit;
        return Ok(torrent_size <= max);
    }
    Ok(false)
}

/// 匹配发布时间分钟数规则。
fn match_publish_time(pub_minutes: f64, publish_time: &str) -> bool {
    let values: Vec<f64> = publish_time
        .split('-')
        .filter_map(|item| item.parse::<f64>().ok())
        .collect();
    if values.len() == 1 {
        return pub_minutes >= values[0];
    }
    if values.len() >= 2 {
        return values[0] <= pub_minutes && pub_minutes <= values[1];
    }
    true
}
