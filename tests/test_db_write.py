import pytest
from app import app, db, Client, Batch

@pytest.fixture()
def client_ctx():
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with app.app_context():
        db.create_all()
        yield

def test_insert_and_read(client_ctx):
    c = Client(google_id="GID", email="a@b.c", name="A",
               token="t", refresh_token="r", token_uri="u",
               client_id="cid", client_secret="sec", scopes="s")
    db.session.add(c); db.session.commit()

    b = Batch(client_id=c.id, subject="S", body="B")
    db.session.add(b); db.session.commit()

    assert Client.query.count() == 1
    assert Batch.query.first().subject == "S"