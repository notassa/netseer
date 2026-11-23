"""UI layout changes: log out in the topbar, severity chips, and the alert-class bar chart markup."""

from netseer.tests.test_devices import analysed  # noqa: F401


def test_logout_form_in_topbar_not_sidebar(analysed):
    client, _ = analysed
    page = client.get("/alerts").text
    assert "sidebar-foot" not in page
    topbar = page.split('<header class="topbar">', 1)[1].split("</header>", 1)[0]
    assert 'action="/logout"' in topbar
    assert "Log out" in topbar


def test_severity_chips_in_alert_table(analysed):
    client, _ = analysed
    page = client.get("/alerts").text
    assert 'class="band high">High' in page
    assert 'class="band medium">Medium' in page
    assert 'class="band low">Low' in page


def test_severity_chip_macro():
    from netseer.src.api.deps import templates

    chip = templates.env.get_template("macros.html").module.severity_chip
    four = str(chip(4))
    assert 'class="band note"' in four and ">Info<" in four
    assert ">7<" in str(chip(7))
    assert "unknown" in str(chip(None))


def test_static_files_are_revalidated(analysed):
    client, _ = analysed
    assert client.get("/static/js/app.js").headers["cache-control"] == "no-cache"


def test_settings_groups_keep_every_section_and_field(analysed):
    client, _ = analysed
    page = client.get("/settings").text
    for title in ("Personal", "Access", "System", "Danger", "Incident building",
                  "Capture", "Network", "Display", "Session"):
        assert title in page
    for tab in ("tab-theme", "tab-accounts", "tab-config", "tab-ai",
                "tab-kb", "tab-oui", "tab-detonate"):
        assert f'id="{tab}"' in page
    for name in ("aggregation_gap_s", "correlation_window_min", "half_life_days",
                 "max_upload_mb", "live_interval_s", "lan_cidrs", "inside_rules",
                 "mac_lookup_online", "data_unit"):
        assert f'name="{name}"' in page
    assert "Still to come: data retention" in page


def test_mobile_menu_markup(analysed):
    client, _ = analysed
    page = client.get("/alerts").text
    assert 'id="mobile-menu"' in page
    assert 'aria-controls="app-sidebar"' in page
    assert 'id="app-sidebar"' in page
    assert 'id="nav-scrim"' in page
    assert 'aria-label="Log out"' in page
