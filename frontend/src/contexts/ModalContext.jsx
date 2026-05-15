import React, { createContext, useContext, useState, useCallback } from 'react';

const ModalContext = createContext(null);

export function ModalProvider({ children }) {
  const [modal, setModal] = useState(null);
  const [drawer, setDrawer] = useState(null);

  const openModal = useCallback((content) => setModal(content), []);
  const closeModal = useCallback(() => setModal(null), []);
  const openDrawer = useCallback((content) => setDrawer(content), []);
  const closeDrawer = useCallback(() => setDrawer(null), []);

  return (
    <ModalContext.Provider value={{ openModal, closeModal, openDrawer, closeDrawer }}>
      {children}
      {modal && (
        <div className="modal-bd open" id="modal-bd" onClick={e => { if (e.target.id === 'modal-bd') closeModal(); }}>
          <div className="modal open">
            {typeof modal === 'string'
              ? <div dangerouslySetInnerHTML={{ __html: modal }} />
              : modal}
          </div>
        </div>
      )}
      {drawer && (
        <>
          <div className="drawer-bd open" onClick={closeDrawer} />
          <aside className="drawer open">
            {typeof drawer === 'string'
              ? <div dangerouslySetInnerHTML={{ __html: drawer }} />
              : drawer}
          </aside>
        </>
      )}
    </ModalContext.Provider>
  );
}

export function useModal() {
  return useContext(ModalContext);
}
