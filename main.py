from fastapi import FastAPI
from symmetric.keys import symmetric_router
from symmetric.symmetric_messages import symmetric_messages_router
from asymmetric.keys import asymmetric_router
from asymmetric.asymmetric_messages import asymmetric_messages_router

app = FastAPI()
app.include_router(symmetric_router)
app.include_router(symmetric_messages_router)
app.include_router(asymmetric_router)
app.include_router(asymmetric_messages_router)


@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/hello/{name}")
async def say_hello(name: str):
    return {"message": f"Hello {name}"}
