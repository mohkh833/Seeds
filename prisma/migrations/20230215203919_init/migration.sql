-- AlterTable
ALTER TABLE "User" ADD COLUMN     "resetToken" TEXT,
ADD COLUMN     "resetTokenExpiry" TEXT,
ALTER COLUMN "refreshToken" DROP NOT NULL;
