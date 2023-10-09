import express, {Express} from 'express';
import bodyParser from 'body-parser';
import fs from 'fs/promises';
import {readFileSync} from 'fs';
import path from 'path';
import { convertPkcs12, generateCertificate, tempfolderWrapper } from './openssl';

type Client = {
    id: string;
    private_key: string;
    preshared_key: string;
    name: string;
    email: string;
    allocated_ips: string[];
    allowed_ips: string[];
    extra_allowed_ips: string[];
    use_server_dns: boolean;
    enabled: boolean;
    created_at: string;
    updated_at: string;
};

const config: {
    server_port: number;
    wireguard_db_path: string;
    ca_cert_path: string;
    ca_key_path: string;
    new_cert_validity_days: number;
} = JSON.parse(readFileSync(path.join(__dirname, '..', 'config.json')).toString('ascii'));

async function findClient(preshared_key: string): Promise<Client|null> {
    const dir = path.join(__dirname, config.wireguard_db_path, 'clients');
    for (let fname of await fs.readdir(dir)) {
        let client = <Client> JSON.parse((await fs.readFile(path.join(dir, fname))).toString('ascii'));
        if (client.preshared_key == preshared_key) {
            return client;
        }
    }
    return null;
}

const app: Express = express();
app.use(bodyParser.urlencoded({extended: true}));
app.set('view engine', 'ejs');

app.get('/', async (req, res) => {
    res.contentType('html');
    res.render('index');
});

app.post<{}, {}, {preshared_key: string}>('/', async (req, res) => {
    let client = await findClient(req.body.preshared_key);
    if (client) {
        console.log(`Generating mTLS cert for "${client.name}".`);

        await tempfolderWrapper(async(tempFolder) => {
            const cert = await generateCertificate({
                email: client!.email,
                validityDays: config.new_cert_validity_days,
                caCertPath: config.ca_cert_path,
                caPrivateKeyPath: config.ca_key_path
            }, tempFolder);

            const pfx = await convertPkcs12({
                name: client!.name,
                caCertPath: config.ca_cert_path,
                certPath: cert.certPath,
                privateKeyPath: cert.privateKeyPath
            });

            res.contentType('application/x-pkcs12');
            res.setHeader('Content-Disposition', `attachment; filename="${client!.name}.pfx"`);
            res.send(pfx);
        });
    } else {
        console.log('Invalid input.');
        res.render('index', {error: 'The submitted key is not valid.'});
    }
});

app.listen(config.server_port);
