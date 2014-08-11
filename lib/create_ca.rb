#!/usr/bin/env ruby
require 'certificate_authority'
require 'require_all'

module CreateCA
  def write_main(file, cert)
    File.open(file, 'w') do |phile|
      phile.write cert.to_pem
    end
  end

  def write_private(file, cert)
    File.open(file, 'w') do |phile|
      phile.write cert.key_material.private_key.to_pem
    end
  end

  def write_public(file, cert)
    File.open(file, 'w') do |phile|
      phile.write cert.key_material.public_key.to_pem
    end
  end
end

# Including the CreateCA module means you can call its methods directly,
# so CreateCA::write_public becomes simply write_public, etc.
include CreateCA

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

cert_files = {
  root_cert => { main:        'ssl/root_ca.cert.pem',
                 private_key: 'ssl/root_ca-private.key.pem',
                 public_key:  'ssl/root_ca-public.key.pem' 
               },

  intermediate_cert => { main:        'ssl/intermediate_ca.cert.pem',
                         private_key: 'ssl/intermediate_ca-private.key.pem',
                         public_key:  'ssl/intermediate_ca-public.key.pem' 
                       },

  plain_cert =>  { main:        'ssl/sites/website.cert.pem',
                   private_key: 'ssl/sites/website-private.akey.pem',
                   public_key:  'ssl/sites/website-public.key.pem'
                 }
}

cert_files.each do |cert, files|
  write_main(files[:main], cert)
  write_private(files[:private_key], cert)
  write_public(files[:public_key], cert)
end

File.open('ssl/ca-chain', "w") do |file|
  file.write root_cert.to_pem
  file.write intermediate_cert.to_pem
end

# verify output with
# openssl verify -verbose -purpose sslserver -CAfile ca-chain website.cert
