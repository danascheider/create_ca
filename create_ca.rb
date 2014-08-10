#!/usr/bin/env ruby
require 'certificate_authority'

# Info for the 3 certs:
cert_data = [
  { common_name: 'Dummy CA Root Certificate',
    serial_number: 1,
    signing_entity: true,
    signing_profile: {'extensions' => { 'keyUsage' => {'usage' => ['critical', 'keyCertSign']}}}
  },
  {
    common_name: 'Dummy Intermediate Certificate',
    serial_number: 2,
    signing_entity: true,
    parent: certs[0],
    signing_profile: {'extensions' => {'keyUsage' => {'usage' => ['critical', 'keyCertSign']}}}
  },
  {
    common_name: 'http://mydomain.com',
    serial_number: 3
    parent: certs[1]
  }
]

certs = []

cert_data.each do |hash|
  cert = CertificateAuthority::Certificate.new
  cert.subject.common_name = hash[:common_name]
  cert.serial_number.number = hash[:serial_number]
  cert.key_material.generate_key
  cert.parent = hash[:parent]
  cert.signing_entity = hash[:signing_entity]
  cert.sign!(hash[:signing_profile])
  certs << cert
end

root_cert, intermediate_cert, plain_cert = certs[0], certs[1], certs[2]

File.open('ssl/root_ca.cert.pem', "w") do |file|
  file.write root_cert.to_pem
end

File.open('ssl/root_ca-private.key.pem', "w") do |file|
  file.write root_cert.key_material.private_key.to_pem
end

File.open('ssl/root_ca-public.key.pem', "w") do |file|
  file.write root_cert.key_material.public_key.to_pem
end

File.open('ssl/intermediate_ca.cert.pem', "w") do |file|
  file.write intermediate_cert.to_pem
end

File.open('ssl/intermediate_ca-private.key.pem', "w") do |file|
  file.write intermediate_cert.key_material.private_key.to_pem
end

File.open('ssl/intermediate_ca-public.key.pem', "w") do |file|
  file.write intermediate_cert.key_material.public_key.to_pem
end

File.open('ssl/sites/website.cert.pem', "w") do |file|
  file.write plain_cert.to_pem
end
File.open('ssl/sites/website-private.key.pem', "w") do |file|
  file.write plain_cert.key_material.private_key.to_pem
end
File.open('ssl/sites/website-public.key.pem', "w") do |file|
  file.write plain_cert.key_material.public_key.to_pem
end

File.open('ssl/ca-chain', "w") do |file|
  file.write root_cert.to_pem
  file.write intermediate_cert.to_pem
end

# verify output with
# openssl verify -verbose -purpose sslserver -CAfile ca-chain website.cert
