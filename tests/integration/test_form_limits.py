"""An urlencoded form is bounded like a multipart one (group 3b, N-23). Before
Starlette 1.3.1, request.form() ignored max_fields and max_part_size for
application/x-www-form-urlencoded, so the login form, which needs no login,
took a body with any number of fields or one field of any size."""

_URLENCODED = {"Origin": "http://testserver",
               "Content-Type": "application/x-www-form-urlencoded"}


class TestTheLoginFormIsBounded:
    """POST /login/submit, the one form reachable without a login."""

    def test_too_many_fields_are_refused(self, client):
        body = "&".join(f"f{i}=x" for i in range(1001)) + "&username=a&password=b"
        response = client.post("/login/submit", content=body, headers=_URLENCODED,
                               follow_redirects=False)
        assert response.status_code == 400

    def test_one_field_over_a_megabyte_is_refused(self, client):
        body = "username=" + "a" * (1024 * 1024 + 1) + "&password=b"
        response = client.post("/login/submit", content=body, headers=_URLENCODED,
                               follow_redirects=False)
        assert response.status_code == 400

    def test_a_login_form_is_still_read(self, client, admin_user_seeded):
        body = f"username={admin_user_seeded['username']}&password={admin_user_seeded['password']}"
        response = client.post("/login/submit", content=body, headers=_URLENCODED,
                               follow_redirects=False)
        assert response.status_code == 303
