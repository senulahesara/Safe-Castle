import {
	FacebookIcon,
	GithubIcon,
	LinkedinIcon,
} from 'lucide-react';
import Image from 'next/image';
import Link from 'next/link';

export function MinimalFooter() {
	const year = new Date().getFullYear();

	const company = [
		{ title: 'Repo', href: '/repo' },
	];

	const resources = [
		{ title: 'Phishing URL Guardian', href: '/url' },
		{ title: 'Password Strength & Breach Checker', href: '/password' },
		{ title: 'Live Threat Map', href: '/map' },
		{ title: 'SSL / TLS Checker', href: '/ssl' },
		{ title: 'VPN & Proxy Checker', href: '/vpn' },
	];

	const socialLinks = [
		{ icon: <FacebookIcon className="size-4" />, link: 'https://www.facebook.com/senulahesara1' },
		{ icon: <GithubIcon className="size-4" />, link: 'https://github.com/senulahesara' },
		{ icon: <LinkedinIcon className="size-4" />, link: 'https://www.linkedin.com/in/senulahesara/' },
	];

	return (
		<footer className="relative">
			<div className="mx-auto max-w-7xl px-6 md:px-8 md:border-x">
				{/* Top border */}
				<div className="bg-border absolute inset-x-0 h-px w-full" />

				{/* Grid layout */}
				<div className="grid grid-cols-1 md:grid-cols-12 gap-8 py-10">
					{/* Logo + Social */}
					<div className="md:col-span-6 flex flex-col gap-5">
						<Link href="/" className="w-max">
							<Image src="/logoDark.svg" alt="Logo" width={40} height={40} />
						</Link>
						<p className="text-muted-foreground max-w-md font-mono text-sm leading-relaxed">
							Your Castle Against Digital Threats
						</p>
						<div className="flex gap-2">
							{socialLinks.map((item, i) => (
								<a
									key={i}
									className="hover:bg-accent rounded-md border p-1.5 transition"
									target="_blank"
									href={item.link}
								>
									{item.icon}
								</a>
							))}
						</div>
					</div>

					{/* Resources */}
					<div className="md:col-span-3">
						<span className="text-muted-foreground mb-2 block text-xs uppercase tracking-wide">
							Tools
						</span>
						<div className="flex flex-col gap-1">
							{resources.map(({ href, title }, i) => (
								<a
									key={i}
									className="w-max py-1 text-sm duration-200"
									href={href}
								>
									{title}
								</a>
							))}
						</div>
					</div>

					{/* Company */}
					<div className="md:col-span-3">
						<span className="text-muted-foreground mb-2 block text-xs uppercase tracking-wide">
							Devolopers
						</span>
						<div className="flex flex-col gap-1">
							{company.map(({ href, title }, i) => (
								<a
									key={i}
									className="w-max py-1 text-sm duration-200"
									href={href}
								>
									{title}
								</a>
							))}
						</div>
					</div>
				</div>

				{/* Bottom border */}
				<div className="bg-border absolute inset-x-0 h-px w-full" />

				{/* Bottom copyright */}
				<div className="flex justify-center pt-4 pb-6">
					<p className="text-muted-foreground text-sm font-light">
						Safe Castle | {year}
					</p>
				</div>
			</div>
		</footer>
	);
}
