# Phase 1 Structural and Import Verification Tests for LEAKLOCK.
import importlib
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def test_required_files_and_directories_exist() -> None:
    required_paths = [
        'app.py',
        'requirements.txt',
        'README.md',
        '.gitignore',
        '.env.example',
        'pages/1_Security_Scanner.py',
        'pages/2_Policy_Manager.py',
        'pages/3_Audit_Dashboard.py',
        'pages/4_About.py',
        'core/__init__.py',
        'services/__init__.py',
        'config/__init__.py',
        'config/settings.py',
        'data/sample_prompts.json',
        'tests/test_app_structure.py',
        'hardware/rtl',
        'hardware/tb',
        'hardware/sim',
        'hardware/synthesis',
        'hardware/physical',
        'hardware/interface',
        'hardware/README.md',
        'docs/architecture.md',
    ]
    for rel_path in required_paths:
        target = PROJECT_ROOT / rel_path
        assert target.exists(), f'Missing required project path: {rel_path}'

def test_configuration_can_be_imported() -> None:
    settings = importlib.import_module('config.settings')
    assert settings.APP_NAME == 'LEAKLOCK'
    assert 'Phase' in settings.CURRENT_PHASE
    assert settings.SCANNER_ENABLED is True
    assert set(settings.PLANNED_POLICIES.keys()) == {'ALLOW', 'REDACT', 'BLOCK'}

def test_packages_and_app_import_without_server() -> None:
    core_pkg = importlib.import_module('core')
    services_pkg = importlib.import_module('services')
    app_module = importlib.import_module('app')
    assert hasattr(core_pkg, '__version__')
    assert hasattr(services_pkg, '__version__')
    assert callable(getattr(app_module, 'main', None))
    assert callable(getattr(app_module, 'load_sample_prompts', None))

def test_sample_prompts_json_is_valid() -> None:
    sample_file = PROJECT_ROOT / 'data' / 'sample_prompts.json'
    with sample_file.open('r', encoding='utf-8') as file:
        payload = json.load(file)
    assert 'metadata' in payload
    assert 'samples' in payload
    assert isinstance(payload['samples'], list)
    assert len(payload['samples']) >= 3
    for item in payload['samples']:
        assert 'id' in item
        assert 'category' in item
        assert 'expected_future_policy' in item
        assert item['expected_future_policy'] in {'ALLOW', 'REDACT', 'BLOCK'}
        assert 'prompt_text' in item


def test_light_theme_configuration_and_no_dark_mode_css():
    """Verify .streamlit/config.toml and all UI files enforce the exact light palette and contain no dark theme colors."""
    config_toml = PROJECT_ROOT / ".streamlit" / "config.toml"
    assert config_toml.exists(), ".streamlit/config.toml must exist to set Streamlit native light theme"
    toml_text = config_toml.read_text(encoding="utf-8")

    assert 'base = "light"' in toml_text
    assert 'backgroundColor = "#FEF8DD"' in toml_text
    assert 'primaryColor = "#90D5FF"' in toml_text
    assert 'secondaryBackgroundColor = "#FFFFFF"' in toml_text
    assert 'textColor = "#30343B"' in toml_text

    services_text = (PROJECT_ROOT / "services" / "__init__.py").read_text(encoding="utf-8")
    required_palette_hex = (
        "#FEF8DD",
        "#90D5FF",
        "#FFDBBB",
        "#E1F8DC",
        "#F1CFE3",
        "#F7D8BA",
        "#30343B",
        "#FFFFFF",
    )
    for hex_code in required_palette_hex:
        assert hex_code in services_text, f"Missing required light palette color {hex_code} in services/__init__.py"

    forbidden_dark_hex = ("#0E1117", "#161B22", "#262730")
    ui_files = [
        PROJECT_ROOT / "app.py",
        PROJECT_ROOT / "services" / "__init__.py",
        PROJECT_ROOT / "pages" / "1_Security_Scanner.py",
        PROJECT_ROOT / "pages" / "2_Policy_Manager.py",
        PROJECT_ROOT / "pages" / "3_Audit_Dashboard.py",
        PROJECT_ROOT / "pages" / "4_About.py",
    ]
    for fpath in ui_files:
        content = fpath.read_text(encoding="utf-8")
        for dark_hex in forbidden_dark_hex:
            assert dark_hex not in content.upper(), f"Forbidden dark color {dark_hex} found in {fpath}"
        if fpath.name != "__init__.py":
            assert "apply_light_theme(st)" in content, f"{fpath} must call apply_light_theme(st)"

