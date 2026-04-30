package com.cryptomobile.config;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;

/**
 * Thread-safe configuration store.
 *
 * <p>Configuration is kept in memory as a {@link Config} instance, serialized
 * to JSON and persisted in the Burp project file via
 * {@code api.persistence().extensionData()} under a single key.
 *
 * <p>Handler threads read via {@link #get()} which returns an immutable
 * snapshot under a read lock. UI mutations go through {@link #update(Consumer)}
 * which acquires the write lock, applies the mutation, snapshots, and
 * persists.
 */
public final class ConfigStore {

    private static final String PERSIST_KEY = "cryptomobile.config.v1";

    private final MontoyaApi api;
    private final Gson gson = new GsonBuilder().setPrettyPrinting().serializeNulls().create();
    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private final CopyOnWriteArrayList<Consumer<Config>> listeners = new CopyOnWriteArrayList<>();

    /** Current in-memory snapshot (always a defensive copy suitable for readers). */
    private volatile Config snapshot;

    public ConfigStore(MontoyaApi api) {
        this.api = api;
        this.snapshot = load();
    }

    private Config load() {
        try {
            PersistedObject data = api.persistence().extensionData();
            String raw = data.getString(PERSIST_KEY);
            if (raw == null || raw.isBlank()) {
                api.logging().logToOutput("[CryptoChef] No saved config found — using defaults.");
                return new Config();
            }
            Config c = gson.fromJson(raw, Config.class);
            // Snapshot heals any nulls from stale on-disk JSON (e.g. missing
            // scopeRules, bodyLocation on ScopeRule, etc.) and gives us a
            // fully-initialised working copy.
            return c != null ? c.snapshot() : new Config();
        } catch (Exception e) {
            api.logging().logToError("[CryptoChef] Failed to load config — using defaults. " + e);
            return new Config();
        }
    }

    private void persist(Config c) {
        try {
            String json = gson.toJson(c);
            api.persistence().extensionData().setString(PERSIST_KEY, json);
        } catch (Exception e) {
            api.logging().logToError("[CryptoChef] Failed to persist config: " + e);
        }
    }

    /** Returns the latest snapshot — cheap, lock-free read. */
    public Config get() {
        return snapshot;
    }

    /** Atomically mutate the config under the write lock and fire listeners. */
    public void update(Consumer<Config> mutator) {
        lock.writeLock().lock();
        try {
            // Mutator operates on a working copy so listeners never see a half-applied state.
            Config working = snapshot.snapshot();
            mutator.accept(working);
            Config frozen  = working.snapshot();
            this.snapshot  = frozen;
            persist(frozen);
        } finally {
            lock.writeLock().unlock();
        }
        fire();
    }

    /** Replace the whole config wholesale (e.g. Import). */
    public void replace(Config next) {
        lock.writeLock().lock();
        try {
            Config frozen = next.snapshot();
            this.snapshot = frozen;
            persist(frozen);
        } finally {
            lock.writeLock().unlock();
        }
        fire();
    }

    public void addListener(Consumer<Config> l)    { listeners.add(l); }
    public void removeListener(Consumer<Config> l) { listeners.remove(l); }

    private void fire() {
        Config c = snapshot;
        for (Consumer<Config> l : listeners) {
            try { l.accept(c); } catch (Exception e) { api.logging().logToError("[CryptoChef] Listener error: " + e); }
        }
    }

    public Gson gson() { return gson; }
}
