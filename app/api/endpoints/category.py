from fastapi import APIRouter, Depends
from app import schemas
from app.chain.tmdb import TmdbChain
from app.db.models import User
from app.db.user_oper import get_current_active_superuser, get_current_active_user
from app.schemas.category import CategoryConfig

router = APIRouter()


@router.get("/", summary="获取分类策略配置", response_model=schemas.Response)
def get_category_config(_: User = Depends(get_current_active_user)):
    """
    获取分类策略配置
    """
    config = TmdbChain().load_category_config()
    return schemas.Response(success=True, data=config.model_dump())


@router.post("/", summary="保存分类策略配置", response_model=schemas.Response)
def save_category_config(config: CategoryConfig, _: User = Depends(get_current_active_superuser)):
    """
    保存分类策略配置
    """
    if TmdbChain().save_category_config(config):
        return schemas.Response(success=True, message="保存成功")
    else:
        return schemas.Response(success=False, message="保存失败")
