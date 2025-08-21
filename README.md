# python-vault-postgresql
Demo for Hashicorp Vault for 3 tier application.

# postgresql docker container
    !sudo docker network create vault-demo-net
    
    !sudo docker run --name demo-postgres \
      --network vault-demo-net \
      -e POSTGRES_PASSWORD=demo \
      -p 5432:5432 \
      -d postgres
    
    !sudo docker ps

# create table inside the psql container
    sql = """
    CREATE TABLE employees (
        id SERIAL PRIMARY KEY,
        name TEXT,
        role TEXT,
        email TEXT,
        phone_number TEXT,
        ssn TEXT,
        address TEXT
    );
    
    -- Insert sample data (using placeholder encrypted values)
    INSERT INTO employees (name, role, email, phone_number, ssn, address) 
    VALUES ('Bob', 'Manager', 'encrypted-email', 'encrypted-phone', 'encrypted-ssn', 'encrypted-address');
    """
    
    # Pipe SQL string into docker psql
    !echo "{sql}" | sudo docker exec -i demo-postgres psql -U postgres

# HashiCorp Vault OSS docker container
    !docker run --name vault-dev \
      --network vault-demo-net \
      -p 8200:8200 \
      -e 'VAULT_DEV_ROOT_TOKEN_ID=root' \
      -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' \
      -d hashicorp/vault
    
    !docker ps

# HashiCorp Vault enterprise docker container
    !sudo docker run -d \
      --cap-add=IPC_LOCK \
      -e VAULT_DEV_ROOT_TOKEN_ID=root \
      -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
      -e VAULT_LICENSE_PATH=/vault/vault.hclic \
      -p 8200:8200 \
      -v /home/vedant/Testing/vault-demo/vault-ent-demo/vault.hclic:/vault/vault.hclic \
      --name vault-enterprise \
      --network vault-demo-net \
      hashicorp/vault-enterprise:latest
    
    !sudo docker ps

# vault secrets enable (DB)
    !docker exec vault-enterprise sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root vault secrets enable -path=mydb database"

# vault dynamic creds
    %%sh
    sudo docker exec -i vault-enterprise sh <<'EOF'
    export VAULT_ADDR='http://127.0.0.1:8200'
    export VAULT_TOKEN='root'
    
    vault write mydb/config/postgres \
      plugin_name=postgresql-database-plugin \
      allowed_roles="my-role" \
      connection_url='postgresql://{{username}}:{{password}}@demo-postgres:5432/postgres?sslmode=disable' \
      username="postgres" \
      password="demo"
    
    vault write mydb/roles/my-role \
      db_name="postgres" \
      creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT USAGE ON         SCHEMA public TO \"{{name}}\"; GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.employees TO \"{{name}}\"; GRANT USAGE ON         SEQUENCE public.employees_id_seq TO \"{{name}}\";" \
      default_ttl="1h" \
      max_ttl="24h"
    
    vault read mydb/creds/my-role
    EOF

# test the vault dynamic creds
    !sudo docker exec -it demo-postgres env PGPASSWORD='iakN-uhxnYTG7vfprnMD' psql -U v-token-my-role-0ycGzdJEicJzneDWDAI0-1755506570     -d postgres -c "SELECT * FROM employees;"

# vault secrets enable (transit and transform)
    !sudo docker exec -i vault-enterprise sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root vault secrets enable -path=transit transit"
    !sudo docker exec -i vault-enterprise sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root vault secrets enable -path=transform transform"
    
    !sudo docker exec -i vault-enterprise sh -c "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root vault write -f transit/keys/employee-key"

# for transit and transform use case
    %%sh
    sudo docker exec -i vault-enterprise sh <<'EOF'
    # Set Vault environment
    export VAULT_ADDR='http://127.0.0.1:8200'
    export VAULT_TOKEN='root'
    
    # Create SSN template
    vault write transform/template/ssn-template \
      type=regex \
      pattern='(\d{5})(\d{4})' \
      encode_format='$1$2' \
      decode_formats=last-four='$2' \
      alphabet=numerics
    
    # Create SSN FPE transformation
    vault write transform/transformations/fpe/ssn-fpe \
      template=ssn-template \
      tweak_source=internal \
      allowed_roles=masking-role
    
    # Create phone number template
    vault write transform/template/phone-template \
      type=regex \
      pattern='(\d{10})' \
      encode_format='$1' \
      decode_formats=full='$1' \
      alphabet=numerics
    
    # Create phone number FPE transformation
    vault write transform/transformations/fpe/phone-fpe \
      template=phone-template \
      tweak_source=internal \
      allowed_roles=masking-role
    
    # Update the masking-role to include both transformations
    vault write transform/role/masking-role \
      transformations=ssn-fpe,phone-fpe
    
    EOF

# Build docker image and run the container
    !docker build -t demo-app .
    
    !docker run -d \
      --name demo-app \
      --network vault-demo-net \
      -p 5000:5000 \
      demo-app

