import yaml
from app.core.config import settings
from app.core.module import ModuleManager
from app.log import logger
from app.schemas.category import CategoryConfig

HEADER_COMMENTS = """####### 配置说明 #######
# 1. 该配置文件用于配置电影和电视剧的分类策略，配置后程序会按照配置的分类策略名称进行分类，配置文件采用yaml格式，需要严格符合语法规则
# 2. 配置文件中的一级分类名称：`movie`、`tv` 为固定名称不可修改，二级名称同时也是目录名称，会按先后顺序匹配，匹配后程序会按这个名称建立二级目录
# 3. 支持的分类条件：
#   `original_language` 语种，具体含义参考下方字典
#   `production_countries` 国家或地区（电影）、`origin_country` 国家或地区（电视剧），具体含义参考下方字典
#   `genre_ids` 内容类型，具体含义参考下方字典
#   `release_year` 发行年份，格式：YYYY，电影实际对应`release_date`字段，电视剧实际对应`first_air_date`字段，支持范围设定，如：`YYYY-YYYY`
#   themoviedb 详情API返回的其它一级字段
# 4. 配置多项条件时需要同时满足，一个条件需要匹配多个值是使用`,`分隔
# 5. !条件值表示排除该值

"""

class CategoryHelper:
    def __init__(self):
        self._config_path = settings.CONFIG_PATH / 'category.yaml'

    def load(self) -> CategoryConfig:
        """
        加载配置
        """
        config = CategoryConfig()
        if not self._config_path.exists():
            return config
        try:
            with open(self._config_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if data:
                    config = CategoryConfig(**data)
        except Exception as e:
            logger.error(f"Load category config failed: {e}")
        return config

    def save(self, config: CategoryConfig) -> bool:
        """
        保存配置
        """
        data = config.model_dump(exclude_none=True)
        try:
            with open(self._config_path, 'w', encoding='utf-8') as f:
                f.write(HEADER_COMMENTS)
                yaml.dump(data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
            # 触发 themoviedb CategoryHelper 重新加载配置
            themoviedb_module = ModuleManager().get_running_module("TheMovieDbModule")
            if themoviedb_module and hasattr(themoviedb_module, 'category'):
                themoviedb_module.category.init()
                logger.info("已触发 CategoryHelper 重新加载配置")
            return True
        except Exception as e:
            logger.error(f"Save category config failed: {e}")
            return False
