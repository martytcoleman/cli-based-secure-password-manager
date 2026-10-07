import ui


# with colors off (piped output, NO_COLOR) the text comes through untouched
def test_plain_when_color_off(monkeypatch):
    monkeypatch.setattr(ui, "USE_COLOR", False)
    assert ui.style("saved.", ui.GREEN) == "saved."


# with colors on it's wrapped in the escape codes and always reset at the end
def test_wrapped_when_color_on(monkeypatch):
    monkeypatch.setattr(ui, "USE_COLOR", True)
    assert ui.style("saved.", ui.GREEN) == "\033[32msaved.\033[0m"


# a styled password still contains the exact password, colors don't change the text
def test_secret_shows_exact_value(monkeypatch, capsys):
    monkeypatch.setattr(ui, "USE_COLOR", True)
    ui.secret("password", "s3cret!")
    assert "s3cret!" in capsys.readouterr().out
