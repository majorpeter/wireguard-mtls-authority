import express, {Express, Request, Response} from 'express';
import bodyParser from 'body-parser';
import fs from 'fs/promises';
import path from 'path';

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

const config = {
    server_port: 8080,
    wireguard_db_path: '../db' //TODO
};

const static_path = path.join(__dirname, '..', 'static');

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

app.get('/', async (req, res) => {
    res.contentType('html');
    res.send(await fs.readFile(path.join(static_path, 'index.html')));
});

app.post<{}, {}, {preshared_key: string}>('/', async (req, res) => {
    let c = await findClient(req.body.preshared_key);
    if (c) {
        console.log(c);
        res.sendStatus(200);
    } else {
        res.send('Private key not valid');
    }
});

app.listen(config.server_port);
