require 'sinatra'
require 'sqlite3'
require 'jwt'
require 'openssl'
require 'json'

# Coloque a sua porta favorita aqui!
set :port, 3000
set :public_folder, 'www'

# Coloque sua chave JWT aqui!
JWT_SECRET = 'JWT_SECRET_THERE'

# Você pode usar
# $ ruby dev/gen-key
# para gerar uma chave para criptografia!
CIPHER_KEY = ['30d0d2df830f692b2541ad972dcdd4233f0cf0baee2101d0f4f0dc9dd59ba9ce'].pack('H*')

# Validar se a chave para criptografar está pronta
unless CIPHER_KEY.bytesize == 32
  puts 'A chave deve ter exatamente 32 bytes (64 caracteres hexadecimais).'
  exit(1)
end

# Inicializar o database para armazenar os tokens
# OBS: Você precisa criar um arquivo numa pasta data, com arquivo tokens.db
DB = SQLite3::Database.new('./data/tokens.db')
DB.execute <<-SQL
  CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT
  )
SQL

def generate_token_aes(email, senha)
  iv = OpenSSL::Random.random_bytes(16)
  cipher = OpenSSL::Cipher.new('aes-256-cbc')
  cipher.encrypt
  cipher.key = CIPHER_KEY
  cipher.iv = iv
  encrypted = cipher.update("#{email}:#{senha}") + cipher.final
  (iv + encrypted).unpack1('H*')
end

def decrypt_token_aes(token_hex)
  token = [token_hex].pack('H*')
  iv = token[0..15]
  encrypted = token[16..-1]

  decipher = OpenSSL::Cipher.new('aes-256-cbc')
  decipher.decrypt
  decipher.key = CIPHER_KEY
  decipher.iv = iv
  decipher.update(encrypted) + decipher.final
end

# Gerar jwt
def generate_token_jwt(email, senha)
  payload = { email: email, senha: senha, exp: Time.now.to_i + 3600 }
  JWT.encode(payload, JWT_SECRET, 'HS256')
end

get '/' do
  redirect '/index.html'
end

get '/html' do
  redirect '/h'tml/index.html'
end

get '/html/' do
  redirect '/html/index.html'
end

get '/crypt1' do
  # Aqui ele meio que pega o email e senha que está nos parâmetros da requisição
  email = params['email']
  senha = params['senha']
  # Caso não tiver
  unless email && senha
    return {
      message: 'Para fazer a primeira criptografia você precisa de passar uma senha e um email.',
      status: 'Error'
    }.to_json
  end

  { jwtToken: generate_token_jwt(email, senha) }.to_json
end

get '/crypt2' do
  email = params['email']
  senha = params['senha']
  crypt1 = params['crypt1']

  unless email && senha && crypt1
    return {
      message: 'Para segunda criptografia você precisa passar um email, senha e a primeira criptografia.',
      status: 'Error'
    }.to_json
  end

  begin
    decoded = JWT.decode(crypt1, JWT_SECRET, true, { algorithm: 'HS256' }).first
    raise JWT::DecodeError if decoded['email'] != email || decoded['senha'] != senha

    { tokenAES: generate_token_aes(email, senha) }.to_json
  rescue JWT::DecodeError
    return {
      message: 'Token JWT inválido',
      status: 'Error'
    }.to_json
  end
end

get '/register' do
  token_reg = params['tokenReg']

  unless token_reg
    return {
      message: 'O token precisa ser passado para prosseguir com o registro.',
      status: 'Error'
    }.to_json
  end

  begin
    decoded_token = decrypt_token_aes(token_reg)

    unless decoded_token
      return {
        message: 'Token inválido ou não descriptografado corretamente.',
        status: 'Error'
      }.to_json
    end

    # Vê se já existe contas com o mesmo email
    rows = DB.execute('SELECT token FROM tokens')
    email_exists = rows.any? do |row|
      decrypt_token_aes(row.first) == decoded_token
    rescue StandardError
      false
    end

    if email_exists
      return {
        message: 'E-mail já registrado.',
        status: 'Error'
      }.to_json
    end

    # Caso não, ele vai registrar
    DB.execute('INSERT INTO tokens (token) VALUES (?)', [token_reg])
    { message: 'Registrado com sucesso!' }.to_json
  rescue StandardError => e
    puts "Error: #{e.message}"
    return {
      message: 'Erro ao processar token.',
      status: 'Error'
    }.to_json
  end
end

get '/login' do
  token_reg = params['tokenReg']
  # Caso não exista o token AES
  unless token_reg
    return {
      message: 'Token é necessário',
      status: 'Error'
    }.to_json
  end
  # Se houver o token
  begin
    decoded_token = decrypt_token_aes(token_reg)
    rows = DB.execute('SELECT token FROM tokens')

    token_match = rows.any? do |row|
      decrypt_token_aes(row.first) == decoded_token
    rescue StandardError
      false
    end
    # Se achar o token
    if token_match
      {
        message: 'Login com Sucesso',
        status: 'Success'
      }.to_json
    else
      # Caso não
      {
        message: 'Token não encontrado',
        status: 'Error'
      }.to_json
    end
  rescue StandardError => e
    puts "Error: #{e.message}"
    return {
      message: 'Erro ao decodificar o token',
      status: 'Error'
    }.to_json
  end
end
