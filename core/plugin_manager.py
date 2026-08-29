"""
Plugin Manager
Manages custom vulnerability scanner plugins
"""

import importlib.util
import inspect
import re
import stat
from typing import Dict, List, Optional, Type
from pathlib import Path
from utils.logger import get_logger

logger = get_logger(__name__)


class PluginBase:
    """Base class for all vulnerability scanner plugins."""
    
    # Plugin metadata
    name: str = "Unknown Plugin"
    version: str = "1.0.0"
    author: str = "Unknown"
    description: str = "No description"
    
    def __init__(self, http_client, config: Dict):
        """
        Initialize plugin.
        
        Args:
            http_client: HTTP client instance
            config: Configuration dictionary
        """
        self.http_client = http_client
        self.config = config
        self.plugin_config = config.get('plugins', {}).get(self.get_plugin_id(), {})
    
    @classmethod
    def get_plugin_id(cls) -> str:
        """Get unique plugin identifier."""
        return cls.__name__.lower().replace('plugin', '')
    
    def is_enabled(self) -> bool:
        """Check if plugin is enabled in configuration."""
        return self.plugin_config.get('enabled', False)
    
    def scan(self, url: str, context: Dict) -> List[Dict]:
        """
        Scan URL for vulnerabilities.
        
        Args:
            url: Target URL
            context: Scan context including response data
            
        Returns:
            List of discovered vulnerabilities
        """
        raise NotImplementedError("Plugin must implement scan() method")
    
    def get_info(self) -> Dict:
        """Get plugin information."""
        return {
            'id': self.get_plugin_id(),
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description,
            'enabled': self.is_enabled()
        }


class PluginManager:
    """Manages loading and execution of vulnerability scanner plugins."""
    
    def __init__(self, http_client, config: Dict):
        """
        Initialize plugin manager.
        
        Args:
            http_client: HTTP client instance
            config: Configuration dictionary
        """
        self.http_client = http_client
        self.config = config
        self.plugins: Dict[str, PluginBase] = {}
        manager_config = config.get('plugin_manager', {})
        self.plugin_dir = Path(manager_config.get('plugin_directory', 'plugins'))
        allowed = manager_config.get('allowed_plugins', [])
        self.allowed_plugins = allowed if isinstance(allowed, list) else []
        
    def load_plugins(self) -> int:
        """
        Load all plugins from plugin directory.
        
        Returns:
            Number of plugins loaded
        """
        if not self.plugin_dir.exists():
            logger.info(f"Plugin directory not found: {self.plugin_dir}")
            return 0

        try:
            plugin_root = self.plugin_dir.resolve(strict=True)
            root_stat = plugin_root.stat()
        except (OSError, RuntimeError) as e:
            logger.error(f"Plugin directory cannot be resolved safely: {e}")
            return 0

        if not plugin_root.is_dir() or self.plugin_dir.is_symlink():
            logger.error("Plugin directory must be a real directory, not a symlink")
            return 0
        if stat.S_IMODE(root_stat.st_mode) & stat.S_IWOTH:
            logger.error("Plugin directory is world-writable; refusing to load plugins")
            return 0

        allowed_files = []
        for configured_name in self.allowed_plugins:
            name = str(configured_name or "").strip()
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.py", name):
                logger.warning(f"Ignoring invalid allowed plugin filename: {name!r}")
                continue
            allowed_files.append(name)
        if not allowed_files:
            logger.warning(
                "Plugin manager is enabled but plugin_manager.allowed_plugins is empty; "
                "no plugin code will be imported"
            )
            return 0
        
        loaded_count = 0

        for plugin_name in dict.fromkeys(allowed_files):
            plugin_file = plugin_root / plugin_name
            try:
                if (
                    not plugin_file.is_file()
                    or plugin_file.is_symlink()
                    or plugin_file.resolve(strict=True).parent != plugin_root
                ):
                    logger.warning(f"Allowed plugin is not a safe regular file: {plugin_name}")
                    continue
                if stat.S_IMODE(plugin_file.stat().st_mode) & stat.S_IWOTH:
                    logger.warning(f"Allowed plugin is world-writable; skipping: {plugin_name}")
                    continue
            except (OSError, RuntimeError) as e:
                logger.warning(f"Unable to validate allowed plugin {plugin_name}: {e}")
                continue

            try:
                for plugin_class in self._load_plugin_classes(plugin_file):
                    plugin_instance = plugin_class(self.http_client, self.config)
                    if not plugin_instance.is_enabled():
                        logger.info(
                            f"Allowed plugin class is disabled in plugins config: "
                            f"{plugin_instance.get_plugin_id()}"
                        )
                        continue
                    plugin_id = plugin_instance.get_plugin_id()
                    self.plugins[plugin_id] = plugin_instance
                    loaded_count += 1
                    logger.info(f"Loaded plugin: {plugin_instance.name} v{plugin_instance.version}")
            except Exception as e:
                logger.error(f"Error loading plugin {plugin_file.name}: {e}")

        logger.info(f"Loaded {loaded_count} plugin(s)")
        return loaded_count

    def _load_plugin_classes(self, plugin_file: Path) -> List[Type[PluginBase]]:
        try:
            spec = importlib.util.spec_from_file_location(plugin_file.stem, plugin_file)
            if not spec or not spec.loader:
                return []

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            found = [
                obj
                for name, obj in inspect.getmembers(module)
                if (
                    inspect.isclass(obj)
                    and issubclass(obj, PluginBase)
                    and obj is not PluginBase
                )
            ]
            if not found:
                logger.warning(f"No PluginBase subclass found in {plugin_file.name}")
            return found
        
        except Exception as e:
            logger.error(f"Error loading plugin file {plugin_file.name}: {e}")
            return []
    
    def get_enabled_plugins(self) -> List[PluginBase]:
        """Get list of enabled plugins."""
        return [plugin for plugin in self.plugins.values() if plugin.is_enabled()]
    
    def get_plugin(self, plugin_id: str) -> Optional[PluginBase]:
        """Get plugin by ID."""
        return self.plugins.get(plugin_id)
    
    def scan_with_plugins(self, url: str, context: Dict) -> List[Dict]:
        """
        Run all enabled plugins against URL.
        
        Args:
            url: Target URL
            context: Scan context
            
        Returns:
            List of vulnerabilities found by plugins
        """
        vulnerabilities = []
        enabled_plugins = self.get_enabled_plugins()
        
        for plugin in enabled_plugins:
            try:
                logger.debug(f"Running plugin: {plugin.name}")
                plugin_vulns = plugin.scan(url, context)
                vulnerabilities.extend(plugin_vulns)
            
            except Exception as e:
                logger.error(f"Error running plugin {plugin.name}: {e}")
        
        return vulnerabilities
    
    def list_plugins(self) -> List[Dict]:
        """Get information about all loaded plugins."""
        return [plugin.get_info() for plugin in self.plugins.values()]

