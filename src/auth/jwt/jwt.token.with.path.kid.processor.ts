import { EntityManager } from '@mikro-orm/core';
import { Logger } from '@nestjs/common';
import { decode, encode } from 'jwt-simple';
import { JwtHeader } from './jwt.header';
import { JwtTokenProcessor as JwtTokenProcessor } from './jwt.token.processor';
import * as fs from 'fs';


export class JwtTokenWithPathKIDProcessor extends JwtTokenProcessor {
  private static readonly KID: string = 'jwt.secret.txt';
  
  constructor(private readonly em: EntityManager, private key: string) {
    super(new Logger(JwtTokenWithPathKIDProcessor.name));
  }

  async validateToken(token: string): Promise<any> {
    this.log.debug('Call validateToken');

    const [header, payload] = this.parse(token);
    this.log.debug(`Header kid is ${header.kid}`);

    const keyPath = `./config/keys/${header.kid}`
    const key = fs.readFileSync(keyPath, 'utf8')

    return decode(token, key, false, 'HS256');
  }

  async createToken(payload: unknown): Promise<string> {
    this.log.debug('Call createToken');
    const header: JwtHeader = {
      alg: 'HS256',
      kid: `${JwtTokenWithPathKIDProcessor.KID}`,
      typ: 'JWT',
    };
    const token = encode(payload, this.key, 'HS256', {
      header,
    });
    return token;
  }
}
