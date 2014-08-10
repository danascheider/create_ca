#!/usr/bin/env ruby
require 'certificate_authority'

# Generate root_cert CA using example code at https://github.com/cchandler/certificate_authority
root_cert = CertificateAuthority::Certificate.new
root_cert.subject.common_name= "Dummy CA Root Certificate"
root_cert.serial_number.number=1
root_cert.key_material.generate_key
root_cert.signing_entity = true
signing_profile = {"extensions" => {"keyUsage" => {"usage" => ["critical", "keyCertSign"] }} }
root_cert.sign!(signing_profile)

# Create an intermediate_cert CA
intermediate_cert = CertificateAuthority::Certificate.new
intermediate_cert.subject.common_name= "Dummy Intermediate Certificate"
intermediate_cert.serial_number.number=2
intermediate_cert.key_material.generate_key
intermediate_cert.signing_entity = true
intermediate_cert.parent = root_cert
signing_profile = {"extensions" => {"keyUsage" => {"usage" => ["critical", "keyCertSign"] }} }
intermediate_cert.sign!(signing_profile)

# Create an actual web site cert
# This will get done many times using the same intermediate certificate
# We don't want to re-generate the root and intermediate CAs each time
plain_cert = CertificateAuthority::Certificate.new
plain_cert.subject.common_name= "http://mydomain.com"
plain_cert.serial_number.number=3
plain_cert.key_material.generate_key
plain_cert.parent = intermediate_cert
plain_cert.sign!

File.open('ssl/root_ca.cert.pem', "w") do |file|
  file.write root_cert.to_pem
end
File.open('ssl/root_ca.cert.x509', "w") do |file|
  file.write root_cert
end
File.open('ssl/root_ca-private.key.pem', "w") do |file|
  file.write root_cert.key_material.private_key.to_pem
end
File.open('ssl/root_ca-private.key.x509', "w") do |file|
  file.write root_cert.key_material.private_key
end
File.open('ssl/root_ca-public.key.pem', "w") do |file|
  file.write root_cert.key_material.public_key.to_pem
end
File.open('ssl/root_ca-public.key.x509', "w") do |file|
  file.write root_cert.key_material.public_key
end

File.open('ssl/intermediate_ca.cert.pem', "w") do |file|
  file.write intermediate_cert.to_pem
end
File.open('ssl/intermediate_ca.cert.x509', "w") do |file|
  file.write intermediate_cert
end
File.open('ssl/intermediate_ca-private.key.pem', "w") do |file|
  file.write intermediate_cert.key_material.private_key.to_pem
end
File.open('ssl/intermediate_ca-private.key.x509', "w") do |file|
  file.write intermediate_cert.key_material.private_key
end
File.open('ssl/intermediate_ca-public.key.pem', "w") do |file|
  file.write intermediate_cert.key_material.public_key.to_pem
end
File.open('ssl/intermediate_ca-public.key.x509', "w") do |file|
  file.write intermediate_cert.key_material.public_key
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
