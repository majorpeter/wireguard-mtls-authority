import fs from 'fs/promises';
import { spawn } from 'child_process';
import path from 'path';

const _opensslDebugEnabled = false;

async function openssl(params: string[], stdin: string|null = null): Promise<{data: Buffer, error: Buffer}> {
    return new Promise((resolve, reject) => {
        const stdout: Buffer[] = [];
        const stderr: Buffer[] = [];

        if (_opensslDebugEnabled) {
            console.log('openssl ' + params.join(' '));
        }
        const openSSLProcess = spawn('openssl', params);

        openSSLProcess.stdout.on('data', (data: Buffer) => {
            stdout.push(data);
        });

        openSSLProcess.stderr.on('data', (data: Buffer) => {
            stderr.push(data);
        });

        openSSLProcess.on('close', (code) => {
            if (code != 0) {
                reject(new Error(Buffer.concat(stderr).toString()));
            }
            resolve({data: Buffer.concat(stdout), error: Buffer.concat(stderr)});
        });
    });
}

export async function tempfolderWrapper(callback: (tempFolder: string) => Promise<void>) {
    const dir = await fs.mkdtemp('/tmp/wgmtlsa');
    try {
        await callback(dir);
    } finally {
        await fs.rm(dir, {
            recursive: true,
            force: true
        });
    }
}

export async function extractCaData(caCertPath: string): Promise<{
    C?: string;
    ST?: string;
    L?: string;
    O?: string;
    emailAddress?: string;
    notAfter?: string;
}> {
    const caCertData = (await openssl(['x509', '-in', caCertPath, '-noout', '-text'])).data.toString();
    const lines = caCertData.split('\n');
    const subjectLine = lines.filter(s => s.indexOf('Subject:') != -1)[0];
    const notAfterLine = lines.filter(s => s.indexOf('Not After :') != -1)[0];

    let result: {[k: string]: string} = {};
    for (const s of subjectLine.substring(subjectLine.indexOf('Subject:') + 'Subject:'.length).split(',')) {
        const key = s.split(' = ')[0].substring(1);
        const value = s.split(' = ')[1];
        result[key] = value;
    }

    result.notAfter = notAfterLine.substring(notAfterLine.indexOf(':') + 2);
    return result;
}

export async function generateCertificate(params: {
    email: string,
    validityDays: number,
    caCertPath: string;
    caPrivateKeyPath: string;
}, workingDir: string): Promise<{
    privateKeyPath: string;
    certPath: string;
}> {
    const privKeyPath = path.join(workingDir, 'key.pem');
    const csrConfigPath = path.join(workingDir, 'csr.conf');
    const csrPath = path.join(workingDir, 'req.csr');
    const certPath = path.join(workingDir, 'cert.crt');

    const caData = await extractCaData(params.caCertPath);

    await fs.writeFile(csrConfigPath,
`[req]
default_bits = 4096
distinguished_name = dn
prompt             = no
req_extensions = req_ext

[dn]
C="${caData.C}"
ST="${caData.ST}"
L="${caData.L}"
O="${caData.O}"
emailAddress="${params.email}"

[req_ext]
subjectAltName = @alt_names
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyAgreement
extendedKeyUsage = critical, clientAuth

[alt_names]
DNS.0 = ${params.email.replace('@', '.')}
`);

    await openssl([
        'req',
        '-nodes', '-newkey', 'rsa:4096',
        '-keyout', privKeyPath,
        '-days', params.validityDays.toString(),
        '-config', csrConfigPath,
        '-out', csrPath,
    ]);

    await openssl([
        'x509', '-req', '-sha512',
        '-days', params.validityDays.toString(),
        '-extensions', 'req_ext', '-extfile', csrConfigPath,
        '-CA', params.caCertPath, '-CAkey', params.caPrivateKeyPath,
        '-in', csrPath, '-out', certPath]);

    //console.log((await openssl(['x509', '-in', certPath, '-noout', '-text'])).data.toString('ascii'));

    return {
        privateKeyPath: privKeyPath,
        certPath: certPath
    };
}

export async function convertPkcs12(params: {
    caCertPath: string;
    certPath: string;
    privateKeyPath: string;
    name: string,
}): Promise<Buffer> {
    return (await openssl([
        'pkcs12', '-in', params.certPath, '-certfile', params.caCertPath,
        '-inkey', params.privateKeyPath,
        '-export', '-passout', 'pass:',
        '-name', params.name,
        '-legacy'   // required for openssl v3
    ])).data;
}
