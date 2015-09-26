import Crypto from "crypto";

let errorType = (name) => (message) => {
  let error = Error();
  error.name = name;
  error.message = message;
  return error;
};

let InvalidAlgorithmError = errorType("InvalidAlgorithmError");
let MalformedJWTError = errorType("MalformedJWTError");
let InvalidJWTError = errorType("InvalidJWTError");
let ExpiredJWTError = errorType("ExpiredJWTError");

let isFunc = (func) => func &&
  ({}).toString.call(func) === "[object Function]";

let b64Encode = (string) => {
  return new Buffer(string)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
};

let b64Decode = (string, enc) => {
  if (string.length % 4 > 0) {
    return b64Decode(string + "=");
  } else {
    return new Buffer(string.replace(/-/g, "+").replace(/\_/g, "/"), "base64")
      .toString(enc);
  }
};

let genHmacSign = (algo) => (data, secret) => {
  return Crypto.createHmac(algo, secret).update(data).digest("base64");
};

let genHmacVerify = (algo) => (data, secret, signature) => {
  return genHmacSign(algo)(data, secret) === signature;
};

let mapSign = {
  hmac256: genHmacSign("sha256"),
  hmac384: genHmacSign("sha384"),
  hmac512: genHmacSign("sha512")
};

let sign = (payload, secret, algo, opts) => {
  opts = opts || {};
  let sign = mapSign[algo];
  if (!sign) {
    throw InvalidAlgorithmError("Invalid algorithm. Available algorithms: " +
      Object.keys(mapSign));
  }
  let header = {
    issued: Math.floor(Date.now() / 1000),
    expires: opts.expires
  };
  let body = b64Encode(JSON.stringify(header)) + "." +
    b64Encode(JSON.stringify(payload));
  let signature = b64Encode(sign(body, secret));
  return body + "." + signature;
};

let mapVerify = {
  hmac256: genHmacVerify("sha256"),
  hmac384: genHmacVerify("sha384"),
  hmac512: genHmacVerify("sha512")
};

let verify = (jwt, secret, algo, opts) => {
  opts = opts || {};
  let verify = mapVerify[algo];
  if (!verify) {
    throw InvalidAlgorithmError("Invalid algorithm. Available algorithms: " +
      Object.keys(mapVerify));
  }
  let parts = jwt.split(".");
  if (parts.length !== 3) {
    throw MalformedJWTError("Malformed JWT.");
  }
  let signature = b64Decode(parts[2]);
  if (!verify(parts[0] + "." + parts[1], secret, signature)) {
    throw InvalidJWTError("JWT has invalid signature.");
  }
  let header = b64Decode(parts[0]);
  if (header.expires &&
      Math.floor(Date.now() / 1000) > header.issued + header.expires) {
    throw ExpiredJWTError("JWT is expired.");
  }
  return JSON.parse(b64Decode(parts[1]));
};

let decode = (jwt) => {
  let parts = jwt.split(".");
  if (parts.length !== 3) {
    throw MalformedJWTError("Malformed JWT.");
  }
  return JSON.parse(b64Decode(parts[1]));
};

export {
  sign,
  verify,
  decode,
  InvalidAlgorithmError,
  MalformedJWTError,
  InvalidJWTError,
  ExpiredJWTError
};
