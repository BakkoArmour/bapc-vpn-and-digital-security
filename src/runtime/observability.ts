// Imported first by every long-running service so errors and crashes reach BAPC Observability (see
// src/infrastructure/error-reporting.ts). A side-effect import on purpose: it must run before anything else can throw.
import {installErrorReporting} from "../infrastructure/error-reporting.js";
installErrorReporting();
