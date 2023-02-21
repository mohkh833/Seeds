import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { UserRepository } from 'src/user/repositories/user.repository';
import { PrismaService } from 'src/prisma/prisma.service';
export type JwtPayload = {
    sub: number;
    email: string;
};

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
    constructor(private prisma: PrismaService) {
        const extractJwtFromCookie = (req) => {
            let token = null;
            if (req && req.cookies) {
                token = req.cookies['access_token'];
            }
            return token || ExtractJwt.fromAuthHeaderAsBearerToken()(req);
        };

        super({
            ignoreExpiration: false,
            secretOrKey: process.env.JWT_ACCESS_SECRET,
            jwtFromRequest: extractJwtFromCookie,
        });
    }

    async validate(payload: JwtPayload) {
        const user = await this.prisma.user.findFirst({
            where: {
				id: payload.sub
			}
        });

        if (!user) throw new UnauthorizedException('Please log in to continue');

        return {
            id: payload.sub,
            email: payload.email,
        };
    }
}