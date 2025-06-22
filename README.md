# Urdimbre_Backend

## Urdimbre - API REST para gestión de usuarios 

### Descripción

Urdimbre es una asociación creada por y para personas trans, no binarias e intersex. Su objetivo es promover una red de actividades de ocio, cultura, deporte y tiempo libre desde una perspectiva comunitaria, inclusiva y segura.

Nuestra misión es la creación y coordinación de actividades deportivas, artísticas y culturales para la comunidad trans, no binaria e intersexual. Buscamos dar visibilidad y espacio a profesionales de la comunidad y a quienes les atienden sin prejuicios, fortaleciendo el tejido comunitario mediante eventos relevantes en la ciudad y sus alrededores.

---

### Objetivos del proyecto

Este proyecto consiste en una API REST para la gestión de usuarios y autenticación, pensada para soportar los procesos de registro, login, gestión de perfiles, actividades, eventos, profesionales y administración de usuarios con un panel de permisos en la plataforma de Urdimbre.

---

### Tecnologías

- Java 17+
- Spring Boot (Web, Security, Data JPA)
- Spring Security para autenticación y autorización
- JWT para manejo de tokens de acceso
- Validaciones con Hibernate Validator
- SLF4J / Logback para logging
- OpenAPI / Swagger para documentación API
- Base de datos con JPA/Hibernate (configurable)

---

### Estructura principal de seguridad del API

#### 1. AuthController (`/api/auth`)

Maneja la autenticación y registro de usuarios con características principales:

- Registro público con código de invitación obligatorio
- Control de rate limiting para proteger contra abuso
- Validaciones exhaustivas con mensajes claros y logs detallados
- Login con manejo de rate limiting por IP y por usuario
- Manejo de excepciones específicas para errores comunes y errores internos

**Endpoints principales:**

| Método | Ruta         | Descripción                  |
|--------|--------------|------------------------------|
| POST   | `/register`  | Registro de nuevo usuario     |
| POST   | `/login`     | Login y obtención de tokens JWT |

---

#### 2. UserController (`/api/users`)

Gestiona usuarios y perfiles con funcionalidades administrativas y de usuario autenticado:

- Obtener todos los usuarios (solo ADMIN)
- Obtener usuario por ID
- Obtener usuario autenticado (`/me`)
- Crear usuario (solo ADMIN, sin código de invitación)
- Actualizar datos del usuario
- Cambiar roles de usuarios (solo ADMIN)
- Eliminar usuario (solo ADMIN)
- Cambiar contraseña de usuario

**Endpoints principales:**

| Método | Ruta                      | Descripción                      | Acceso             |
|--------|---------------------------|---------------------------------|--------------------|
| GET    | `/`                       | Obtener todos los usuarios       | ADMIN              |
| GET    | `/{id}`                   | Obtener usuario por ID           | Usuario autenticado |
| GET    | `/me`                     | Obtener datos del usuario actual | Usuario autenticado |
| POST   | `/`                       | Crear usuario sin código de invitación | ADMIN       |
| PUT    | `/{id}`                   | Actualizar usuario               | Usuario autenticado |
| PUT    | `/{id}/roles`             | Actualizar roles de usuario      |



Equipo de dessarrollo: 

Eva - https://www.linkedin.com/in/eva-sisalli-guzman/
Alba -https://www.linkedin.com/in/rieradipefullstack/
Einar - https://www.linkedin.com/in/einartech/overlay/photo/
Mariana - https://www.linkedin.com/in/mariana-marin-1b6268348/
Maria - https://www.linkedin.com/in/mariabongoll/
