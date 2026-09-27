import random
import re
import time


def test_generate_api_key_page_renders(client):
    response = client.get("/a02/generate-api-key")
    assert response.status_code == 200


def test_generated_key_is_reproducible_from_a_nearby_timestamp(client):
    before = int(time.time())
    response = client.post("/a02/generate-api-key")
    after = int(time.time())
    assert response.status_code == 200

    body = response.data.decode()
    match = re.search(r"([0-9a-f]{32})", body)
    assert match is not None
    real_key = match.group(1)

    # Simulates an attacker who only knows the approximate generation
    # second (e.g. from the HTTP response's own Date header in a real
    # deployment), searching a small window of candidate timestamps --
    # never the 32-character key space itself.
    reproduced = False
    for t in range(before - 2, after + 3):
        random.seed(t)
        guess = "".join(random.choices("0123456789abcdef", k=32))
        if guess == real_key:
            reproduced = True
            break
    assert reproduced, "the real key was not reproducible from any nearby timestamp"
