from app import app, db, Client, Batch
from datetime import datetime

with app.app_context():
    print("Clients before:", Client.query.count())
    print("Batches before:", Batch.query.count())

    c = Client(google_id="TESTID", email="x@y.com", name="X",
               token="t", refresh_token="r", token_uri="u",
               client_id="cid", client_secret="sec", scopes="s")
    db.session.add(c); db.session.commit()

    b = Batch(client_id=c.id, subject="Hello", body="World",
              created_at=datetime.utcnow())
    db.session.add(b); db.session.commit()

    print("Clients after :", Client.query.count())
    print("Batches after :", Batch.query.count())

    # clean-up
    db.session.delete(b); db.session.delete(c); db.session.commit()