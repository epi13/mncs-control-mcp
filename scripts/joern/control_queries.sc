@main def controlQueries(cpgFile: String): Unit = {
  importCpg(cpgFile)
  val names = List(
    "resolve_repository", "resolve", "resolve_scope", "run_bounded", "run", "command_argv",
    "start", "stop", "write", "delete", "patch", "dispatch", "invoke", "build_server",
    "terminal_exec", "terminal_start", "dispatch_fabric_job"
  )
  println("METHODS")
  cpg.method.nameExact(names: _*).fullName.l.sorted.foreach(println)
  println("CALLS")
  def sinks = cpg.call.nameExact(
    "Popen", "run", "kill", "killpg", "wait", "resolve", "relative_to", "open", "unlink",
    "rmtree", "move", "copytree", "command_argv", "run_bounded"
  )
  sinks.code.l.sorted.foreach(println)
  println("CONTROL_STRUCTURES")
  cpg.method.nameExact(names: _*).controlStructure.code.l.sorted.foreach(println)
  println("DOMINATORS")
  sinks.dominatedBy.code.l.sorted.take(200).foreach(println)
  println("POST_DOMINATORS")
  sinks.postDominatedBy.code.l.sorted.take(200).foreach(println)
  println("CONTROL_DEPENDENCIES")
  sinks.controlledBy.code.l.sorted.take(200).foreach(println)
  println("DATA_FLOWS")
  val sources = cpg.method.nameExact(names: _*).parameter
  sinks.argument.reachableByFlows(sources).l.take(100).foreach(flow =>
    println(flow.elements.map(_.code).mkString(" -> "))
  )
  println("SUBPROCESS")
  cpg.call.code(".*Popen.*").code.l.sorted.foreach(println)
}
