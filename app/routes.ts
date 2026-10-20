import { type RouteConfig, route } from "@react-router/dev/routes";

export default [
  route(":name?", "routes/home.tsx")
] satisfies RouteConfig;
