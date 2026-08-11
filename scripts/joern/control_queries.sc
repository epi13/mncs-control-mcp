@main def controlQueries(cpgFile: String): Unit = {
  importCpg(cpgFile)
  val names = List("resolve_repository", "run_bounded", "repo_status", "run", "build_server", "dispatch_fabric_job")
  println("METHODS")
  cpg.method.nameExact(names: _*).fullName.l.sorted.foreach(println)
  println("CALLS")
  cpg.call.nameExact("Popen", "kill", "wait", "resolve", "run_bounded").code.l.sorted.foreach(println)
  println("SUBPROCESS")
  cpg.call.code(".*Popen.*").code.l.sorted.foreach(println)
}
