import toast from "react-hot-toast";
import { useAuthStore } from "../store/useAuthStore";
import { useState } from "react";
import { Eye, EyeOff, Loader2, Lock, Mail, MessageSquare } from "lucide-react";
import { Link } from "react-router";

export default function LoginPage() {
  const [showPassword, setShowPassword] = useState(false);
  const { isLoggedIn, login } = useAuthStore();
  const [formData, setFormData] = useState({
    email: "",
    password: "",
  });

  function validateForm() {
    let regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!formData.email.trim()) return toast.error("Email is required");
    if (!formData.password.trim()) return toast.error("Password is required");
    if (formData.email.trim() < 6)
      return toast.error("Password must be greater than 6");
    if (!regex.test(formData.email)) return toast.error("Invalid email format");

    return true;
  }

  function handleSubmit(e) {
    e.preventDefault();

    const success = validateForm();
    if (success === true) login(formData);
  }

  return (
    <div className="min-h-screen grid lg:grid-cols-2">
      {/* left side */}
      <div className="flex flex-col justify-center mt-12 items-center p-6 sm:p-12">
        <div className="w-full max-w-md space-y-8">
          {/* Logo */}
          <div className="text-center mb-8">
            <div className="flex flex-col items-center gap-2 group">
              <div className="size-12 rounded-xl bg-primary/10 flex items-center justify-center group-hover:bg-primary/20 transition-colors">
                <MessageSquare className="size-6 text-primary" />
              </div>
              <h1 className="text-2xl font-bold mt-2">Welcome back</h1>
              <p className="text-base-content/60">Signin to your account</p>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="form-control">
              <label className="label">
                <span className="label-text font-medium">Email</span>
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Mail className="size-5 text-base-content/40" />
                </div>
                <input
                  type="text"
                  className={`input input-bordered w-full pl-10`}
                  placeholder="you@example.com"
                  value={formData.email}
                  onChange={(e) =>
                    setFormData({ ...formData, email: e.target.value })
                  }
                />
              </div>
            </div>

            <div className="form-control">
              <label className="label">
                <span className="label-text font-medium">Password</span>
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="size-5 text-base-content/40" />
                </div>
                <input
                  type={showPassword ? "text" : "password"}
                  className={`input input-bordered w-full pl-10`}
                  placeholder="*********"
                  value={formData.password}
                  onChange={(e) =>
                    setFormData({ ...formData, password: e.target.value })
                  }
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 pr-3 flex items-center"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? (
                    <EyeOff className="size-5 text-base-content/40" />
                  ) : (
                    <Eye className="size-5 text-base-content/40" />
                  )}
                </button>
              </div>
            </div>

            <button
              type="submit"
              className="btn btn-primary w-full"
              disabled={isLoggedIn}
            >
              {isLoggedIn ? (
                <>
                  <Loader2 className="size-5 animate-spin" />
                  Loading...
                </>
              ) : (
                "Login"
              )}
            </button>
          </form>

          <div className="text-center">
            <p className="text-base-content/60">
              Don&apos;t have an account?{" "}
              <Link to={"/signup"} className="link link-primary">
                Create account
              </Link>
            </p>
          </div>
        </div>
      </div>
      {/* right side */}
      <div className="flex flex-col items-center justify-center p-6">
        <h1 className="text-3xl font-bold mt-2">Join our community</h1>
        <p className="text-base-content/60 p-4 text-center">
          Connect with friends, share moments, and stay in touch with your loved
          ones.
        </p>
      </div>
    </div>
  );
}
