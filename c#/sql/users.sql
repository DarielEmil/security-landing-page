IF DB_ID(N'security_landing_page') IS NULL
BEGIN
    CREATE DATABASE security_landing_page;
END
GO

USE security_landing_page;
GO

IF OBJECT_ID(N'dbo.users', N'U') IS NULL
BEGIN
    CREATE TABLE dbo.users (
        id         UNIQUEIDENTIFIER NOT NULL,
        name       NVARCHAR(120) NOT NULL,
        email      NVARCHAR(160) NOT NULL,
        phone      NVARCHAR(30) NULL,
        province   NVARCHAR(80) NULL,
        created_at DATETIME2(0) NOT NULL CONSTRAINT df_users_created_at DEFAULT SYSDATETIME(),
        updated_at DATETIME2(0) NULL,
        deleted_at DATETIME2(0) NULL,
        CONSTRAINT pk_users PRIMARY KEY (id)
    );

    CREATE UNIQUE INDEX uq_users_email ON dbo.users (email);
    CREATE INDEX idx_users_deleted_at ON dbo.users (deleted_at);
    CREATE INDEX idx_users_province ON dbo.users (province);
END
GO

CREATE OR ALTER TRIGGER trg_users_updated_at
ON dbo.users
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    IF TRIGGER_NESTLEVEL() > 1
    BEGIN
        RETURN;
    END

    UPDATE u
    SET u.updated_at = SYSDATETIME()
    FROM dbo.users AS u
    INNER JOIN inserted AS i ON i.id = u.id;
END
GO
