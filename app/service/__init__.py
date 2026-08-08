"""
应用服务层（service layer）。

承接从 API 端点（app/api/endpoints）下沉的、可独立单元测试的业务/协议逻辑，
使端点退化为薄编排层，便于后续 Rust 重写时作为稳定的移植目标。
"""
