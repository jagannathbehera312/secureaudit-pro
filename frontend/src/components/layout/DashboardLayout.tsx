import React, { useState } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Sidebar } from "./Sidebar";
import { TopNavbar } from "./TopNavbar";

export const DashboardLayout: React.FC = () => {
  const location = useLocation();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  return (
    <div className="flex min-h-screen bg-[#070A12] text-[#F8FAFC] relative overflow-x-hidden bg-grid-cyber">
      {/* Ambient background glow accents inspired by motion.dev */}
      <div className="fixed top-0 left-0 lg:left-64 w-72 sm:w-96 h-72 sm:h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
      <div className="fixed bottom-0 right-0 w-72 sm:w-[500px] h-72 sm:h-[500px] bg-blue-600/5 rounded-full blur-3xl pointer-events-none" />

      {/* Responsive Sidebar (Desktop fixed + Mobile slide-over drawer) */}
      <Sidebar
        mobileOpen={mobileNavOpen}
        onCloseMobile={() => setMobileNavOpen(false)}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 relative z-10 w-full">
        <TopNavbar onOpenMobileNav={() => setMobileNavOpen(true)} />
        <main className="flex-1 p-3.5 sm:p-6 md:p-8 max-w-7xl w-full mx-auto">
          <AnimatePresence mode="wait">
            <motion.div
              key={location.pathname}
              initial={{ opacity: 0, y: 10, scale: 0.995 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -8, scale: 0.995 }}
              transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
            >
              <Outlet />
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
};