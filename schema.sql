--
-- PostgreSQL database dump
--

\restrict YbfDbp2oFBSjNnFywdA8f9kGAmBkix5QrmXSzNvE65JlwuqEGxSOqT7POEIix8L

-- Dumped from database version 17.11 (Debian 17.11-1.pgdg13+2)
-- Dumped by pg_dump version 17.11 (Debian 17.11-1.pgdg13+2)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: affected_products; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.affected_products (
    id integer NOT NULL,
    incident_id integer,
    vendor text,
    product text,
    version text,
    version_start_including text,
    version_start_excluding text,
    version_end_including text,
    version_end_excluding text
);


--
-- Name: affected_products_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.affected_products_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: affected_products_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.affected_products_id_seq OWNED BY public.affected_products.id;


--
-- Name: incidents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.incidents (
    id integer NOT NULL,
    title text NOT NULL,
    source text NOT NULL,
    url text,
    type text,
    description text NOT NULL,
    published timestamp without time zone,
    cvss_score numeric,
    priority integer,
    severity text,
    priority_level text,
    category text,
    vendor text,
    product text,
    required_action text,
    due_date timestamp without time zone,
    date_added timestamp without time zone,
    ransomware_use text,
    cve_id text,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: incidends_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.incidends_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: incidends_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.incidends_id_seq OWNED BY public.incidents.id;


--
-- Name: report_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.report_runs (
    id integer NOT NULL,
    ran_at timestamp without time zone DEFAULT now()
);


--
-- Name: report_runs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.report_runs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: report_runs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.report_runs_id_seq OWNED BY public.report_runs.id;


--
-- Name: subscribers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.subscribers (
    id integer NOT NULL,
    email text NOT NULL,
    active boolean DEFAULT true NOT NULL,
    token uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    confirmed boolean DEFAULT false NOT NULL
);


--
-- Name: subscribers_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.subscribers_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: subscribers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.subscribers_id_seq OWNED BY public.subscribers.id;


--
-- Name: affected_products id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.affected_products ALTER COLUMN id SET DEFAULT nextval('public.affected_products_id_seq'::regclass);


--
-- Name: incidents id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incidents ALTER COLUMN id SET DEFAULT nextval('public.incidends_id_seq'::regclass);


--
-- Name: report_runs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.report_runs ALTER COLUMN id SET DEFAULT nextval('public.report_runs_id_seq'::regclass);


--
-- Name: subscribers id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscribers ALTER COLUMN id SET DEFAULT nextval('public.subscribers_id_seq'::regclass);


--
-- Name: affected_products affected_products_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.affected_products
    ADD CONSTRAINT affected_products_pkey PRIMARY KEY (id);


--
-- Name: incidents incidends_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incidents
    ADD CONSTRAINT incidends_pkey PRIMARY KEY (id);


--
-- Name: report_runs report_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.report_runs
    ADD CONSTRAINT report_runs_pkey PRIMARY KEY (id);


--
-- Name: subscribers subscribers_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscribers
    ADD CONSTRAINT subscribers_email_key UNIQUE (email);


--
-- Name: subscribers subscribers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscribers
    ADD CONSTRAINT subscribers_pkey PRIMARY KEY (id);


--
-- Name: subscribers subscribers_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subscribers
    ADD CONSTRAINT subscribers_token_key UNIQUE (token);


--
-- Name: incidents unique_cve_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incidents
    ADD CONSTRAINT unique_cve_id UNIQUE (cve_id);


--
-- Name: incidents unique_url; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.incidents
    ADD CONSTRAINT unique_url UNIQUE (url);


--
-- Name: affected_products affected_products_incident_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.affected_products
    ADD CONSTRAINT affected_products_incident_id_fkey FOREIGN KEY (incident_id) REFERENCES public.incidents(id);


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: -
--

GRANT USAGE ON SCHEMA public TO cyberwatch_readonly;
GRANT USAGE ON SCHEMA public TO cyberwatch_unsub;


--
-- Name: TABLE affected_products; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.affected_products TO cyberwatch_readonly;


--
-- Name: TABLE incidents; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.incidents TO cyberwatch_readonly;


--
-- Name: TABLE report_runs; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT ON TABLE public.report_runs TO cyberwatch_readonly;


--
-- Name: TABLE subscribers; Type: ACL; Schema: public; Owner: -
--

GRANT DELETE ON TABLE public.subscribers TO cyberwatch_unsub;


--
-- Name: COLUMN subscribers.id; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT(id) ON TABLE public.subscribers TO cyberwatch_unsub;


--
-- Name: COLUMN subscribers.email; Type: ACL; Schema: public; Owner: -
--

GRANT INSERT(email) ON TABLE public.subscribers TO cyberwatch_signup;
GRANT SELECT(email) ON TABLE public.subscribers TO cyberwatch_lookup;


--
-- Name: COLUMN subscribers.active; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT(active),UPDATE(active) ON TABLE public.subscribers TO cyberwatch_unsub;
GRANT SELECT(active) ON TABLE public.subscribers TO cyberwatch_signup;


--
-- Name: COLUMN subscribers.token; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT(token) ON TABLE public.subscribers TO cyberwatch_unsub;
GRANT SELECT(token) ON TABLE public.subscribers TO cyberwatch_signup;
GRANT SELECT(token) ON TABLE public.subscribers TO cyberwatch_lookup;


--
-- Name: COLUMN subscribers.confirmed; Type: ACL; Schema: public; Owner: -
--

GRANT SELECT(confirmed) ON TABLE public.subscribers TO cyberwatch_signup;
GRANT UPDATE(confirmed) ON TABLE public.subscribers TO cyberwatch_unsub;


--
-- Name: SEQUENCE subscribers_id_seq; Type: ACL; Schema: public; Owner: -
--

GRANT USAGE ON SEQUENCE public.subscribers_id_seq TO cyberwatch_signup;


--
-- PostgreSQL database dump complete
--

\unrestrict YbfDbp2oFBSjNnFywdA8f9kGAmBkix5QrmXSzNvE65JlwuqEGxSOqT7POEIix8L

