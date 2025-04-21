require 'securerandom'

# Generate a random 32-byte (256-bit) key
key = SecureRandom.random_bytes(32)
hex_key = key.unpack('H*').first

puts "Chave Hexadecimal de 32 bytes:"
puts hex_key