# Run this server like this: uvicorn api:app --reload

import os
from starlette.middleware.sessions import SessionMiddleware
from fastapi import FastAPI, responses, Response, status, Body, Request
from siwe import siwe
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

origins = [
    "http://localhost",
    "http://localhost:3000",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("SESSION_SECRET_KEY", "change_me")
)


@app.get("/nonce", response_class=responses.PlainTextResponse)
def siwe_nonce(request: Request):
    nonce = siwe.generate_nonce()
    request.session["nonce"] = nonce
    return nonce


@app.post("/verify")
def siwe_verify(request: Request, response: Response, message: str = Body(...), signature: str = Body(...)):
    if not message:
        response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
        return {"message": "Expected prepareMessage object as body."}

    try:
        siwe_message = siwe.SiweMessage(message)
        siwe_message.validate(signature)

        if siwe_message.nonce != request.session.get("nonce", None):
            response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
            return {"message": "Invalid nonce."}

        siwe_dict = {slot: siwe_message.__getattribute__(slot) for slot in siwe_message.__slots__}
        request.session["siwe"] = siwe_dict
        return {}

    except siwe.ExpiredMessage:
        response.status_code = 440
        return {"message": "Message expired."}
    except siwe.InvalidSignature:
        response.status_code = 422
        return {"message": "Invalid signature"}
    except Exception as err:
        response.status_code = 500
        return {"message": f"Unknown error: {err}"}


@app.get("/personal_information", response_class=responses.PlainTextResponse)
def siwe_personal_information(request: Request, response: Response):
    if not request.session.get("siwe", None):
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {"message": "You have to sign in first."}

    return f"""You are authenticated and your address is: {request.session["siwe"]["address"]}"""


if __name__ == "__main__":
    # Use this for debugging purposes only
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8001, log_level="debug", reload=True)
