use actix_web::{dev::ServiceRequest, error, get, post, web, App, Error, HttpResponse, HttpServer};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use actix_web_httpauth::{extractors::bearer::BearerAuth, middleware::HttpAuthentication};

const LLAVE_SECRETA: &str = "12345";

#[derive(Serialize, Deserialize, Debug)]
struct Claims {
    iss: String,
    sub: String,
    exp: usize,
    iat: usize,
    user_id: usize,
}

#[derive(Serialize, Deserialize)]
struct LoginForm {
    usuario: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct LoginResult {
    token: String,
}

fn generar_token(iss: String, sub: String, duracion_en_minutos: i64, user_id: usize) -> String {
    let header = Header::new(Algorithm::HS512);
    let encoding_key = EncodingKey::from_secret(LLAVE_SECRETA.as_ref());

    let exp = (Utc::now() + Duration::minutes(duracion_en_minutos)).timestamp() as usize;
    let iat = Utc::now().timestamp() as usize;

    let my_claims = Claims {
        iss,
        sub,
        exp,
        iat,
        user_id,
    };

    encode(&header, &my_claims, &encoding_key).unwrap()
}

fn validar_token(token: String) -> Result<Claims, jsonwebtoken::errors::Error> {
    let validacion = Validation::new(Algorithm::HS512);
    let decoding_key = DecodingKey::from_secret(LLAVE_SECRETA.as_ref());

    let resultado = decode::<Claims>(&token, &decoding_key, &validacion);

    match resultado {
        Ok(c) => {
            println!("Token es valido");
            Ok(c.claims)
        }
        Err(e) => {
            println!("Token es invalido");
            Err(e)
        }
    }
}

async fn validador(
    req: ServiceRequest,
    credenciales: Option<BearerAuth>,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let Some(credenciales) = credenciales else {
        return Err((error::ErrorBadRequest("no se especifico el token"), req));
    };

    let token = credenciales.token();

    let resultado = validar_token(token.to_owned());

    match resultado {
        Ok(claims) => {
            println!("Los claims son: {:?}", claims);
            return Ok(req);
        }
        Err(e) => {
            println!("el token no es valido: {:?}", e);
            return Err((error::ErrorForbidden("no tiene acceso"), req));
        }
    }
}

#[post("/login")]
async fn login(form: web::Form<LoginForm>) -> HttpResponse {
    if form.usuario == "rusty" && form.password == "fullstack" {
        let iss = "Rusty Full Stack".to_owned();
        let sub = "Prueba".to_owned();
        let duracion_en_minutos: i64 = 5;
        let user_id = 1;

        let token = generar_token(iss, sub, duracion_en_minutos, user_id);

        let respuesta = LoginResult { token };

        HttpResponse::Ok().json(respuesta)
    } else {
        HttpResponse::Unauthorized().body("Login invalido")
    }
}

#[get("/privado")]
async fn privado() -> HttpResponse {
    HttpResponse::Ok().body("privado")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let auth = HttpAuthentication::with_fn(validador);

        App::new()
            .service(login)
            .service(web::scope("/admin").wrap(auth).service(privado))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}