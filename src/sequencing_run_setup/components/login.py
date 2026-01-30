"""Login page UI components."""

from fasthtml.common import *


def LoginPage(error_message: str = ""):
    """
    Render the login page.

    Args:
        error_message: Optional error message to display
    """
    return (
        Title("SeqSetup - Login"),
        Main(
            Div(
                # Logo/Header
                Div(
                    H1("SeqSetup"),
                    P(
                        "Illumina Sequencing Run Configuration",
                        cls="login-subtitle",
                    ),
                    cls="login-header",
                ),
                # Login form
                Form(
                    Div(
                        Label("Username", fr="username"),
                        Input(
                            type="text",
                            name="username",
                            id="username",
                            required=True,
                            autofocus=True,
                            placeholder="Enter your username",
                        ),
                        cls="form-group",
                    ),
                    Div(
                        Label("Password", fr="password"),
                        Input(
                            type="password",
                            name="password",
                            id="password",
                            required=True,
                            placeholder="Enter your password",
                        ),
                        cls="form-group",
                    ),
                    # Error message
                    Div(
                        error_message,
                        cls="error-message",
                    )
                    if error_message
                    else None,
                    Button("Sign In", type="submit", cls="btn-primary btn-login"),
                    action="/login/submit",
                    method="post",
                    cls="login-form",
                ),
                cls="login-card",
            ),
            cls="login-container",
        ),
    )


# CSS for login page (to be added to app_css in app.py)
LOGIN_CSS = """
.login-container {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 1rem;
}

.login-card {
    background: var(--card-bg);
    border-radius: 12px;
    padding: 2.5rem;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
    width: 100%;
    max-width: 400px;
}

.login-header {
    text-align: center;
    margin-bottom: 2rem;
}

.login-header h1 {
    margin: 0;
    color: var(--primary);
    font-size: 2rem;
}

.login-subtitle {
    color: var(--text-muted);
    margin: 0.5rem 0 0;
    font-size: 0.9rem;
}

.login-form .form-group {
    margin-bottom: 1.25rem;
}

.login-form input {
    padding: 0.75rem;
    font-size: 1rem;
}

.btn-login {
    width: 100%;
    padding: 0.875rem;
    font-size: 1rem;
    margin-top: 0.5rem;
}

.login-form .error-message {
    margin-bottom: 1rem;
}
"""
