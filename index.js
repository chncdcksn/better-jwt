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

let encode = (string) => new Buffer(string)
  .toString("base64")
  .replace("=", "")
  .replace("+", "-")
  .replace("/", "_");

let decode = (string, enc) => string.length % 4 > 0 ? decode(string + "=") :
  new Buffer(string.replace("-", "+").replace("_", "/"), "base64")
    .toString(enc);

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
  let body = encode(JSON.stringify(header)) + "." +
    encode(JSON.stringify(payload));
  let signature = encode(sign(body, secret));
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
  let signature = decode(parts[2]);
  if (!verify(parts[0] + "." + parts[1], secret, signature)) {
    throw InvalidJWTError("JWT has invalid signature.");
  }
  let header = decode(parts[0]);
  if (header.expires &&
      Math.floor(Date.now() / 1000) > header.issued + header.expires) {
    throw ExpiredJWTError("JWT is expired.");
  }
  return JSON.parse(decode(parts[1]));
};

export {
  sign,
  verify,
  InvalidAlgorithmError,
  MalformedJWTError,
  InvalidJWTError,
  ExpiredJWTError
};
