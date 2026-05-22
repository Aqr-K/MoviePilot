use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};
use regex::Regex;

/// 捕获正则第一组并转换为整数。
pub(crate) fn capture_i64(regex: &Regex, text: &str) -> Option<i64> {
    regex
        .captures(text)
        .and_then(|caps| caps.get(1))
        .and_then(|value| value.as_str().parse::<i64>().ok())
}

/// 捕获正则所有分组中的整数，用于 S01E02 和范围类 token 的多值识别。
pub(crate) fn capture_all_i64(regex: &Regex, text: &str) -> Vec<i64> {
    let mut values = Vec::new();
    for caps in regex.captures_iter(text) {
        for item in caps.iter().skip(1).flatten() {
            if let Ok(value) = item.as_str().parse::<i64>() {
                values.push(value);
                break;
            }
        }
    }
    values
}

/// 计算范围的开始、结束和总数，保持 Python 侧的倒序交换语义。
pub(crate) fn apply_range_total(
    mut begin: Option<i64>,
    mut end: Option<i64>,
) -> (Option<i64>, Option<i64>, Option<i64>) {
    let total = match (begin, end) {
        (Some(begin_value), Some(end_value)) => {
            if begin_value > end_value {
                begin = Some(end_value);
                end = Some(begin_value);
                Some(begin_value - end_value + 1)
            } else {
                Some(end_value - begin_value + 1)
            }
        }
        (Some(_), None) => Some(1),
        _ => None,
    };
    (begin, end, total)
}

/// 将 Python 对象转换为 usize，用于过滤器下标。
pub(crate) fn py_i64_to_usize(value: &Bound<'_, PyAny>) -> PyResult<usize> {
    let index = value.extract::<i64>()?;
    if index < 0 {
        return Err(PyValueError::new_err("下标不能为负数"));
    }
    Ok(index as usize)
}

/// 从 Python 字典读取可选字符串。
pub(crate) fn get_optional_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<String>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(None);
    };
    if value.is_none() {
        return Ok(None);
    }
    Ok(Some(value.str()?.to_str()?.to_string()))
}

/// 从 Python 字典读取可选整数。
pub(crate) fn get_optional_i64(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<i64>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(None);
    };
    if value.is_none() {
        return Ok(None);
    }
    if let Ok(parsed) = value.extract::<i64>() {
        return Ok(Some(parsed));
    }
    let text = value.str()?.to_str()?.trim().to_string();
    if text.is_empty() {
        return Ok(None);
    }
    Ok(text.parse::<i64>().ok())
}

/// 从 Python 字典读取可选浮点数。
pub(crate) fn get_optional_f64(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<f64>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(None);
    };
    if value.is_none() {
        return Ok(None);
    }
    if let Ok(parsed) = value.extract::<f64>() {
        return Ok(Some(parsed));
    }
    let text = value.str()?.to_str()?.trim().to_string();
    if text.is_empty() {
        return Ok(None);
    }
    Ok(text.parse::<f64>().ok())
}
