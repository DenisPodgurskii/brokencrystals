import { EntityManager } from '@mikro-orm/core';
import { Logger } from '@nestjs/common';
import { decode, encode } from 'jwt-simple';
import { JwtHeader } from './jwt.header';
import { JwtTokenProcessor as JwtTokenProcessor } from './jwt.token.processor';
import { exec } from 'child_process';

export class JwtTokenWithCMDKIDProcessor extends JwtTokenProcessor {
  private static readonly KID: string = 'jwt.secret.txt';

  constructor(private readonly em: EntityManager, private key: string) {
    super(new Logger(JwtTokenWithCMDKIDProcessor.name));
  }

  async validateToken(token: string): Promise<any> {
    this.log.debug('Call validateToken');


    const [header, payload] = this.parse(token);
    this.log.debug(`Header kid is ${header.kid}`);

    const keyPath: string = `./config/keys/${header.kid}`
    let key = await this.getToken(keyPath)

    this.log.error(`key: ${key}`);
    return decode(token, key, false, 'HS256');
  }

  async getToken(path: string): Promise<string> {
    return new Promise((resolve, reject) => {
      exec(`cat ${path}`, (error, stdout, stderr) => {
        if (error) {
          console.warn(error);
        }
        resolve(stdout ? stdout : stderr);
      });
    });
  }

  async createToken(payload: unknown): Promise<string> {
    this.log.debug('Call createToken');
    const header: JwtHeader = {
      alg: 'HS256',
      kid: `${JwtTokenWithCMDKIDProcessor.KID}`,
      typ: 'JWT',
    };
    const token = encode(payload, this.key, 'HS256', {
      header,
    });
    return token;
  }
}
