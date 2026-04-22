import io
import json
import shutil
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from app.agent.middleware.skills import _parse_skill_metadata
from app.core.cache import cached, fresh
from app.core.config import settings
from app.log import logger
from app.utils.http import RequestUtils
from app.utils.singleton import WeakSingleton
from app.utils.url import UrlUtils

_SOURCE_META_FILENAME = ".moviepilot-skill-source.json"
_DEFAULT_BRANCHES = ("main", "master")
_MARKET_CACHE_TTL = 60 * 30


@dataclass
class SkillInfo:
    id: str
    name: str
    description: str
    version: int = 0
    path: str = ""
    source_type: str = "local"
    source_label: str = "本地"
    repo_url: Optional[str] = None
    repo_name: Optional[str] = None
    skill_path: Optional[str] = None
    installed: bool = False
    removable: bool = False


class SkillHelper(metaclass=WeakSingleton):
    """
    技能市场与本地技能管理
    """

    @staticmethod
    def get_user_skills_dir() -> Path:
        """
        返回用户技能目录，所有市场安装的技能都落在这里。
        """
        return settings.CONFIG_PATH / "agent" / "skills"

    @staticmethod
    def get_bundled_skills_dir() -> Path:
        """
        返回仓库内置技能目录。
        """
        return settings.ROOT_PATH / "skills"

    @staticmethod
    def get_market_sources() -> List[str]:
        """
        解析配置中的技能市场列表。
        """
        if not settings.SKILL_MARKET:
            return []
        return [item.strip() for item in settings.SKILL_MARKET.split(",") if item.strip()]

    @staticmethod
    def _ensure_user_skills_dir() -> Path:
        """
        确保用户技能目录存在，供安装和扫描复用。
        """
        skill_dir = SkillHelper.get_user_skills_dir()
        skill_dir.mkdir(parents=True, exist_ok=True)
        return skill_dir

    @staticmethod
    def _normalize_repo_url(repo_url: str) -> Optional[str]:
        """
        将技能市场配置统一归一为 GitHub HTTPS 地址。
        """
        repo_url = (repo_url or "").strip()
        if not repo_url:
            return None
        if repo_url.startswith(("http://", "https://")):
            return repo_url.rstrip("/")
        return f"https://github.com/{repo_url.strip('/')}"

    @staticmethod
    def _parse_market_repo(repo_url: str) -> Optional[dict]:
        """
        解析市场仓库地址，提取仓库、分支和技能根目录信息。
        """
        normalized = SkillHelper._normalize_repo_url(repo_url)
        if not normalized:
            return None
        parsed = urlparse(normalized)
        if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
            logger.warning("暂不支持的技能市场地址：%s", repo_url)
            return None

        parts = [part for part in parsed.path.strip("/").split("/") if part]
        if len(parts) < 2:
            return None

        owner = parts[0]
        repo = parts[1].removesuffix(".git")
        branch = None
        root_path = "skills"
        if len(parts) >= 4 and parts[2] == "tree":
            branch = parts[3]
            if len(parts) > 4:
                root_path = "/".join(parts[4:])

        return {
            "repo_url": f"https://github.com/{owner}/{repo}",
            "repo_name": f"{owner}/{repo}",
            "owner": owner,
            "repo": repo,
            "branch": branch,
            "root_path": root_path.strip("/") or "skills",
        }

    @staticmethod
    def _read_source_meta(skill_dir: Path) -> dict:
        """
        读取技能来源元数据，用于区分本地、市场和内置技能。
        """
        meta_path = skill_dir / _SOURCE_META_FILENAME
        if not meta_path.exists():
            return {}
        try:
            payload = json.loads(meta_path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {}
        except Exception as e:
            logger.warning("读取技能来源元数据失败：%s - %s", meta_path, e)
            return {}

    @staticmethod
    def _write_source_meta(skill_dir: Path, payload: dict) -> None:
        """
        写入技能来源元数据，便于后续展示来源和追踪安装来源。
        """
        meta_path = skill_dir / _SOURCE_META_FILENAME
        meta_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    @staticmethod
    def _is_bundled_skill(skill_id: str) -> bool:
        """
        判断技能是否来自仓库内置目录。
        """
        return (SkillHelper.get_bundled_skills_dir() / skill_id / "SKILL.md").exists()

    def list_local_skills(self) -> List[SkillInfo]:
        """
        扫描本地已安装技能，并补充来源和是否可删除等展示信息。
        """
        skill_root = self._ensure_user_skills_dir()
        results: List[SkillInfo] = []

        for path in sorted(skill_root.iterdir(), key=lambda item: item.name.lower()):
            if not path.is_dir():
                continue
            skill_md = path / "SKILL.md"
            if not skill_md.exists():
                continue
            try:
                content = skill_md.read_text(encoding="utf-8")
            except Exception as e:
                logger.warning("读取技能文件失败：%s - %s", skill_md, e)
                continue

            metadata = _parse_skill_metadata(content, str(skill_md), path.name)
            if not metadata:
                continue

            bundled = self._is_bundled_skill(path.name)
            source_meta = self._read_source_meta(path)
            source_type = "bundled" if bundled else source_meta.get("source", "local")
            if source_type == "market":
                repo_name = source_meta.get("repo_name") or source_meta.get("repo_url")
                source_label = f"市场 · {repo_name}" if repo_name else "市场"
            elif source_type == "bundled":
                source_label = "内置"
            else:
                source_label = "本地"

            results.append(
                SkillInfo(
                    id=path.name,
                    name=metadata["name"],
                    description=metadata["description"],
                    version=metadata["version"],
                    path=str(skill_md),
                    source_type=source_type,
                    source_label=source_label,
                    repo_url=source_meta.get("repo_url"),
                    repo_name=source_meta.get("repo_name"),
                    skill_path=source_meta.get("skill_path"),
                    installed=True,
                    removable=not bundled,
                )
            )

        return results

    def list_market_skills(self, force: bool = False) -> List[SkillInfo]:
        """
        聚合所有市场源的技能，并用本地技能状态标记已安装项。
        """
        local_skills = self.list_local_skills()
        local_ids = {skill.id for skill in local_skills}
        local_names = {skill.name for skill in local_skills}

        deduped: Dict[str, SkillInfo] = {}
        for source in self.get_market_sources():
            with fresh(force):
                market_skills = self._list_market_repo_skills(source)
            for skill in market_skills:
                key = skill.name or skill.id
                if key in deduped:
                    continue
                skill.installed = skill.id in local_ids or skill.name in local_names
                deduped[key] = skill

        return sorted(
            deduped.values(),
            key=lambda item: (
                item.installed,
                (item.repo_name or "").lower(),
                item.name.lower(),
            ),
        )

    @cached(maxsize=16, ttl=_MARKET_CACHE_TTL, skip_empty=True)
    def _list_market_repo_skills(self, repo_url: str) -> List[SkillInfo]:
        """
        读取单个市场仓库中的技能列表。

        仓库按 zip 方式拉取后直接在压缩包内解析，避免落地整个仓库。
        """
        repo = self._parse_market_repo(repo_url)
        if not repo:
            return []

        repo_bytes = self._download_repo_archive(repo)
        if not repo_bytes:
            return []

        try:
            with zipfile.ZipFile(io.BytesIO(repo_bytes)) as zf:
                names = zf.namelist()
                if not names:
                    return []
                root_prefix = names[0].split("/", 1)[0] + "/"
                results: List[SkillInfo] = []
                seen_paths = set()
                for archive_name in names:
                    if not archive_name.endswith("/SKILL.md"):
                        continue
                    if not archive_name.startswith(root_prefix):
                        continue

                    rel_path = archive_name[len(root_prefix):].strip("/")
                    if not rel_path.startswith(f"{repo['root_path'].strip('/')}/"):
                        continue
                    if "/.system/" in f"/{rel_path}/":
                        continue
                    if rel_path in seen_paths:
                        continue
                    seen_paths.add(rel_path)

                    skill_dir = rel_path[: -len("/SKILL.md")]
                    skill_id = Path(skill_dir).name
                    try:
                        content = zf.read(archive_name).decode("utf-8")
                    except Exception as e:
                        logger.warning("读取市场技能失败：%s - %s", archive_name, e)
                        continue

                    metadata = _parse_skill_metadata(
                        content,
                        f"{repo['repo_url']}:{rel_path}",
                        skill_id,
                    )
                    if not metadata:
                        continue

                    results.append(
                        SkillInfo(
                            id=skill_id,
                            name=metadata["name"],
                            description=metadata["description"],
                            version=metadata["version"],
                            path=f"{repo['repo_url']}/tree/{repo['branch']}/{skill_dir}",
                            source_type="market",
                            source_label=f"市场 · {repo['repo_name']}",
                            repo_url=repo["repo_url"],
                            repo_name=repo["repo_name"],
                            skill_path=skill_dir,
                            installed=False,
                            removable=False,
                        )
                    )
                return results
        except Exception as e:
            logger.error("解析技能市场压缩包失败：%s", e)
            return []

    def install_market_skill(self, skill: SkillInfo) -> Tuple[bool, str]:
        """
        将市场技能安装到用户技能目录，并记录来源元数据。
        """
        if not skill.repo_url or not skill.skill_path:
            return False, "技能来源信息不完整，无法安装"

        target_root = self._ensure_user_skills_dir()
        target_dir = target_root / skill.id
        if target_dir.exists():
            return False, f"技能 {skill.id} 已存在"
        if self._is_bundled_skill(skill.id):
            return False, f"技能 {skill.id} 是 MoviePilot 内置技能，不能覆盖安装"

        repo = self._parse_market_repo(skill.repo_url)
        if not repo:
            return False, "技能市场地址无效"

        repo_bytes = self._download_repo_archive(repo)
        if not repo_bytes:
            return False, "下载技能仓库失败，请检查网络连接或 GitHub 配置"

        try:
            with zipfile.ZipFile(io.BytesIO(repo_bytes)) as zf:
                names = zf.namelist()
                if not names:
                    return False, "技能仓库为空"
                root_prefix = names[0].split("/", 1)[0] + "/"
                skill_prefix = f"{root_prefix}{skill.skill_path.strip('/')}/"
                matched = [name for name in names if name.startswith(skill_prefix)]
                if not matched:
                    return False, f"未找到技能目录：{skill.skill_path}"

                target_dir.mkdir(parents=True, exist_ok=False)
                try:
                    wrote = False
                    for archive_name in matched:
                        rel_name = archive_name[len(skill_prefix):]
                        if not rel_name:
                            continue
                        output_path = target_dir / rel_name
                        if archive_name.endswith("/"):
                            output_path.mkdir(parents=True, exist_ok=True)
                            continue
                        output_path.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(archive_name, "r") as src, open(output_path, "wb") as dst:
                            shutil.copyfileobj(src, dst)
                        wrote = True

                    if not wrote or not (target_dir / "SKILL.md").exists():
                        shutil.rmtree(target_dir, ignore_errors=True)
                        return False, "技能目录内容不完整，安装失败"

                    self._write_source_meta(
                        target_dir,
                        {
                            "source": "market",
                            "repo_url": repo["repo_url"],
                            "repo_name": repo["repo_name"],
                            "branch": repo["branch"],
                            "skill_path": skill.skill_path,
                            "installed_at": datetime.now(timezone.utc).isoformat(),
                        },
                    )
                    return True, f"技能 {skill.id} 已安装到 {target_dir}"
                except Exception:
                    shutil.rmtree(target_dir, ignore_errors=True)
                    raise
        except Exception as e:
            logger.error("安装市场技能失败：%s", e)
            return False, f"安装技能失败：{e}"

    def remove_local_skill(self, skill_id: str) -> Tuple[bool, str]:
        """
        删除一个本地技能目录，内置技能会被显式拦截。
        """
        if not skill_id:
            return False, "技能ID不能为空"
        if self._is_bundled_skill(skill_id):
            return False, f"技能 {skill_id} 是 MoviePilot 内置技能，不能删除"

        skill_dir = self._ensure_user_skills_dir() / skill_id
        if not skill_dir.exists():
            return False, f"技能 {skill_id} 不存在"
        if not (skill_dir / "SKILL.md").exists():
            return False, f"{skill_id} 不是有效的技能目录"

        try:
            shutil.rmtree(skill_dir)
            return True, f"技能 {skill_id} 已删除"
        except Exception as e:
            logger.error("删除技能失败：%s", e)
            return False, f"删除技能失败：{e}"

    def _download_repo_archive(self, repo: dict) -> Optional[bytes]:
        """
        下载市场仓库压缩包，并在缺省分支之间做回退尝试。
        """
        branches = [repo.get("branch")] if repo.get("branch") else []
        branches.extend([branch for branch in _DEFAULT_BRANCHES if branch not in branches])
        for branch in branches:
            archive_url = (
                f"https://codeload.github.com/{repo['owner']}/{repo['repo']}/zip/refs/heads/{branch}"
            )
            response = self._request_github(
                url=archive_url,
                repo_name=repo["repo_name"],
                is_api=False,
            )
            if response is not None and response.status_code == 200:
                repo["branch"] = branch
                return response.content
        logger.warning("下载技能市场仓库失败：%s", repo["repo_url"])
        return None

    @staticmethod
    def _request_github(
        url: str,
        repo_name: str,
        is_api: bool = False,
        timeout: int = 30,
    ):
        """
        按代理优先级顺序请求 GitHub 资源，兼容代理和直连场景。
        """
        strategies = []
        headers = settings.REPO_GITHUB_HEADERS(repo=repo_name)
        if not is_api and settings.GITHUB_PROXY:
            proxy_url = f"{UrlUtils.standardize_base_url(settings.GITHUB_PROXY)}{url}"
            strategies.append((proxy_url, {"headers": headers, "timeout": timeout}))
        if settings.PROXY_HOST:
            strategies.append(
                (
                    url,
                    {
                        "headers": headers,
                        "proxies": settings.PROXY,
                        "timeout": timeout,
                    },
                )
            )
        strategies.append((url, {"headers": headers, "timeout": timeout}))

        for target_url, kwargs in strategies:
            try:
                response = RequestUtils(**kwargs).get_res(
                    url=target_url,
                    raise_exception=True,
                )
                if response is not None and response.status_code == 200:
                    return response
            except Exception as e:
                logger.warning("请求技能市场失败：%s - %s", target_url, e)
        return None
