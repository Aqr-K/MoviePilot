use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};

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

/// 将 Python 对象转换为 i64，用于兼容配置里字符串或数字形式的下标。
pub(crate) fn extract_i64(value: &Bound<'_, PyAny>) -> PyResult<Option<i64>> {
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
