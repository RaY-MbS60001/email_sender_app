from app import db, Client, Batch, BatchEmail

# 1. See how many rows exist now
print("Clients :", Client.query.count())
print("Batches :", Batch.query.count())

# 2. Create a throw-away client + batch
c = Client(google_id="TEST123", email="test@x.com", name="Dummy",
           token="tok", refresh_token="ref", token_uri="uri",
           client_id="cid", client_secret="csec", scopes="x")
db.session.add(c); db.session.commit()

b = Batch(client_id=c.id, subject="Hello", body="World")
db.session.add(b); db.session.commit()

print("After insert ► Clients:", Client.query.count(),
      "Batches:", Batch.query.count())

# 3. Clean up
db.session.delete(b); db.session.delete(c); db.session.commit()