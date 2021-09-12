import * as data from './config.json'; //Incluyendo el archivo que contiene los parametros para los request
import fetch from 'node-fetch'; //Modulo para realizar los request 
import { Headers } from 'node-fetch'; //Modulo para armar los Headers de los request

let base64 = require('base-64'); //Variable para codificar en base 64 las credenciales en el Header
let meta; //Variable para el armado de los Headers
let body; //Variable para el armado del cuerpo del request
let tokenJWT = Boolean(JSON.parse(data.tokenJWT)); //Variable para tipo de Token a emitir

//Metodo para obtener Token, devuelve un JSON.
export async function getToken() {
    
    //Definiendo los Headers del request
    meta = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
    };
    //Creando un objeto tipo Header y agregando la variable meta
    const headers = new Headers(meta);

    //Define el tipo de token que se va a emitir en dependencia de lo configurado en los parametros
    if (tokenJWT) {
        //Header para Token JWT
        headers.append(
            'Authorization', 'Basic ' + base64.encode(data.jwt_client_key + ":" + data.jwt_client_secret) //Header para autenticacion basica haciendo uso de los parametros OAuth Client Key y OAuth Client Secret del Proveedor de Servicio para tokens JWT
        );
    } else {
        //Header para token Default
        headers.append(
            'Authorization', 'Basic ' + base64.encode(data.default_client_key + ":" + data.default_client_secret) //Header para autenticacion basica haciendo uso de los parametros OAuth Client Key y OAuth Client Secret del Proveedor de Servicio para tokens Default
        );
    }

    //Definiendo el Body del request
    body = "grant_type=" + data.grant_type + "&username=" + data.username + "&password=" + data.password + "&scope=" + data.scope;

    //Realizando el request, request de tipo asincrono
    try {
        const response = await fetch(data.get_token_URL, {
            method: "POST",
            headers: headers,
            body: body
        });

        const result = await response.json();

        return result;

    } catch (error) {
        //En caso de error este es mostrado en consola
        console.log(error);
    }

}

//Recibe y valida un Token emitido, devuelve un JSON
export async function validateToken(token: string) {

    //Definiendo los Headers
    meta = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'Authorization': 'Basic ' + base64.encode(data.userValidation + ":" + data.passValidation) //Header para autenticacion basica haciendo uso del usuario tokenValidation para validacion de tokens
    };
    //Creando un objeto tipo Header y agregando la variable meta
    const headers = new Headers(meta);

    //Definiendo el Body del request
    body = "token=" + token;

    //Realizando el request, request de tipo asincrono 
    try {
        const response = await fetch(data.validate_token_URL, {
            method: "POST",
            headers: headers,
            body: body,
        });

        const result = await response.json();

        return result;

    } catch (error) {
        //En caso de error este es mostrado en consola
        console.log(error);
    }
}

//Recibe y revoca un Token, el servidor WSO2 IS envia una respuesta vacia
export async function revokeToken(token: string) {

    //Definiendo los Headers del request
    meta = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
    };
    //Creando un objeto tipo Header y agregando la variable meta
    const headers = new Headers(meta);

    //Define el tipo de token que se va a revocar en dependencia de lo configurado en los parametros
    if (tokenJWT) {
        headers.append(
            'Authorization', 'Basic ' + base64.encode(data.jwt_client_key + ":" + data.jwt_client_secret) //Header para autenticacion basica haciendo uso de los parametros OAuth Client Key y OAuth Client Secret del Proveedor de Servicio para tokens JWT
        );
    } else {
        headers.append(
            'Authorization', 'Basic ' + base64.encode(data.default_client_key + ":" + data.default_client_secret) //Header para autenticacion basica haciendo uso de los parametros OAuth Client Key y OAuth Client Secret del Proveedor de Servicio para tokens Default
        );
    }

    //Definiendo el Body del request
    body = "token=" + token;

    //Realizando el request, request de tipo asincrono 
    try {
        return fetch(data.revoke_token_URL, {
            method: "POST",
            headers: headers,
            body: body,
        });

        

    } catch (error) {
        //En caso de error este es mostrado en consola
        console.log(error);

        return false;
    }
}