package com.github.jtraglia.dff;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

/**
 * Native interface to System V shared memory functions.
 */
class SharedMemory {

    /**
     * Interface to native System V shared memory functions.
     */
    interface CLibrary extends Library {
        CLibrary INSTANCE = Native.load("c", CLibrary.class);

        /**
         * Attach to System V shared memory segment.
         *
         * @param shmid shared memory identifier
         * @param shmaddr address to attach at (null for automatic)
         * @param shmflg flags for attachment
         * @return pointer to attached memory, or -1 on error
         */
        Pointer shmat(int shmid, Pointer shmaddr, int shmflg);

        /**
         * Detach from System V shared memory segment.
         *
         * @param shmaddr address of memory to detach
         * @return 0 on success, -1 on error
         */
        int shmdt(Pointer shmaddr);
    }

    private static final CLibrary libc = CLibrary.INSTANCE;

    /**
     * Attach to a System V shared memory segment.
     *
     * @param shmid the shared memory identifier
     * @return pointer to the attached memory
     * @throws RuntimeException if attachment fails
     */
    static Pointer attach(int shmid) {
        Pointer ptr = libc.shmat(shmid, null, 0);
        if (Pointer.nativeValue(ptr) == -1) {
            throw new RuntimeException("Failed to attach to shared memory segment " + shmid);
        }
        return ptr;
    }

    /**
     * Detach from a System V shared memory segment.
     *
     * @param ptr pointer to the memory to detach
     * @throws RuntimeException if detachment fails
     */
    static void detach(Pointer ptr) {
        if (ptr != null && Pointer.nativeValue(ptr) != -1) {
            int result = libc.shmdt(ptr);
            if (result == -1) {
                throw new RuntimeException("Failed to detach from shared memory");
            }
        }
    }
}