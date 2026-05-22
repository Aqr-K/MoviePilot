mod filter;
mod indexer;
mod meta;
mod rss;
mod utils;

use pyo3::prelude::*;

/// 返回扩展是否已成功加载，用于 Python 侧健康检查。
#[pyfunction]
fn is_available() -> bool {
    true
}

/// 注册 MoviePilot Rust 扩展模块。
#[pymodule]
fn moviepilot_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(is_available, m)?)?;
    m.add_function(wrap_pyfunction!(meta::is_anime_fast, m)?)?;
    m.add_function(wrap_pyfunction!(meta::find_metainfo_fast, m)?)?;
    m.add_function(wrap_pyfunction!(meta::parse_video_title_fast, m)?)?;
    m.add_function(wrap_pyfunction!(filter::parse_filter_rule_fast, m)?)?;
    m.add_function(wrap_pyfunction!(filter::filter_torrents_fast, m)?)?;
    m.add_function(wrap_pyfunction!(indexer::build_indexer_search_url_fast, m)?)?;
    m.add_function(wrap_pyfunction!(indexer::parse_indexer_torrents_fast, m)?)?;
    m.add_function(wrap_pyfunction!(rss::parse_rss_items_fast, m)?)?;
    Ok(())
}
